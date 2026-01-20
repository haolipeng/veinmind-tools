# veinmind-malicious 恶意文件扫描插件技术分析

**功能概述**: 使用 ClamAV + VirusTotal 双引擎检测容器镜像中的恶意文件。

**代码位置**: `plugins/go/veinmind-malicious/`

---

## 1. 核心架构 - 双引擎设计

### 1.1 扫描结果统一接口

```go
// plugins/go/veinmind-malicious/sdk/av/common.go:3-8
type ScanResult struct {
    EngineName  string  // 引擎名称
    IsMalicious bool    // 是否恶意
    Description string  // 描述
    Method      string  // 检测方法
}
```

### 1.2 引擎激活检测

```go
// ClamAV 激活检测
func Active() bool {
    if client == nil {
        return false
    }
    return client.Ping() == nil
}

// VirusTotal 激活检测
func Active() bool {
    return client != nil  // 只需检查 API Key 是否配置
}
```

---

## 2. ClamAV 引擎集成

### 2.1 客户端初始化

```go
// plugins/go/veinmind-malicious/sdk/av/clamav/client.go:14-18
var client = func() *clamd.Clamd {
    var CLAMD_ADDRESS = "tcp://" + os.Getenv("CLAMD_HOST") + ":" + os.Getenv("CLAMD_PORT")
    c := clamd.NewClamd(CLAMD_ADDRESS)
    return c
}()
```

**配置方式**:
- `CLAMD_HOST`: ClamAV 服务地址
- `CLAMD_PORT`: ClamAV 服务端口

### 2.2 流式扫描实现

```go
// plugins/go/veinmind-malicious/sdk/av/clamav/client.go:32-70
func ScanStream(stream io.Reader) ([]av.ScanResult, error) {
    abort := make(chan bool, 1)
    response, err := client.ScanStream(stream, abort)
    defer func() {
        close(abort)
    }()

    if err != nil {
        if strings.Contains(err.Error(), "broken pipe") {
            return nil, new(SizeLimitReachedError)
        }
        return nil, err
    }

    ret := make([]clamd.ScanResult, 0, len(response))
    for s := range response {
        if s.Status == clamd.RES_FOUND {
            ret = append(ret, *s)
        } else if s.Status == clamd.RES_ERROR {
            return nil, errors.New(s.Description)
        } else if s.Status == clamd.RES_PARSE_ERROR {
            return nil, new(ResultParseError)
        }
    }

    // 转换为公共结构体
    retCommon := []av.ScanResult{}
    for _, r := range ret {
        commonResult := av.ScanResult{
            EngineName:  "ClamAV",
            Description: r.Description,
            IsMalicious: true,
            Method:      "blacklist",
        }
        retCommon = append(retCommon, commonResult)
    }

    return retCommon, nil
}
```

**特点**:
- 支持流式扫描，无需完整写入临时文件
- 支持中断通道 (abort channel)
- 处理文件大小限制错误

---

## 3. VirusTotal 引擎集成

### 3.1 客户端初始化

```go
// plugins/go/veinmind-malicious/sdk/av/virustotal/client.go:23-31
var client = func() *vt.Client {
    apiKey := os.Getenv("VT_API_KEY")
    if apiKey == "" {
        return nil
    }
    return vt.NewClient(apiKey)
}()
```

**配置方式**:
- `VT_API_KEY`: VirusTotal API 密钥

### 3.2 SHA256 哈希查询

```go
// plugins/go/veinmind-malicious/sdk/av/virustotal/client.go:41-99
func ScanSHA256(ctx context.Context, sha256 string) ([]av.ScanResult, error) {
    var retCommon []av.ScanResult
    done := make(chan struct{})

    if client == nil {
        return nil, errors.New("Virustotal Client Init Failed")
    }

    go func() {
        // 获取文件分析结果
        vtFile, err := client.GetObject(vt.URL("files/%s", sha256))
        if err != nil {
            return
        }

        r, err := vtFile.Get("last_analysis_results")
        if err != nil || r == nil {
            return
        }

        // 解析各引擎检测结果
        rMap := r.(map[string]interface{})
        for _, detail := range rMap {
            detailJson, _ := json.Marshal(detail)

            analysisResult := AnalysisResult{}
            json.Unmarshal(detailJson, &analysisResult)

            if analysisResult.Category == "malicious" {
                commonResult := av.ScanResult{
                    Description: analysisResult.Result,
                    Method:      analysisResult.Method,
                    EngineName:  analysisResult.EngineName,
                    IsMalicious: true,
                }
                retCommon = append(retCommon, commonResult)
            }
        }

        done <- struct{}{}
    }()

    // 超时控制
    select {
    case <-ctx.Done():
        return retCommon, nil
    case <-done:
        return retCommon, nil
    }
}
```

**特点**:
- 基于文件 SHA256 哈希查询，无需上传文件
- 异步查询 + 超时控制
- 解析多引擎检测结果

---

## 4. Docker 镜像分层扫描

### 4.1 Layer 缓存优化

```go
// plugins/go/veinmind-malicious/scanner/malicious/scan.go:29-69
func Scan(image api.Image) (scanReport model.ReportImage, err error) {
    // 检查镜像是否已扫描
    database.GetDbInstance().Preload("Layers").Preload("Layers.MaliciousFileInfos").
        Where("image_id = ?", image.ID()).Find(&scanReport)
    if scanReport.ImageID != "" {
        log.Info(image.ID(), " Has been detected")
        return scanReport, nil
    }

    switch v := image.(type) {
    case *docker.Image:
        dockerImage := v
        for i := 0; i < dockerImage.NumLayers(); i++ {
            // 获取 Layer ID
            layerID, _ := dockerImage.GetLayerDiffID(i)

            // 检查 Layer 是否已扫描
            reportLayer := model.ReportLayer{}
            database.GetDbInstance().Preload("MaliciousFileInfos").
                Where("layer_id", layerID).Find(&reportLayer)

            if reportLayer.LayerID != "" {
                // 复用已有扫描结果
                reportLayerCopy := model.ReportLayer{
                    ImageID:            image.ID(),
                    LayerID:            reportLayer.LayerID,
                    MaliciousFileInfos: reportLayer.MaliciousFileInfos,
                }
                scanReport.Layers = append(scanReport.Layers, reportLayerCopy)
                log.Info("Skip Scan Layer: ", layerID)
                continue
            }

            // 扫描新 Layer
            // ...
        }
    }
}
```

**优化策略**:
1. **镜像级缓存**: 已扫描镜像直接返回结果
2. **Layer 级缓存**: 复用共享 Layer 的扫描结果
3. **避免重复扫描**: 大幅提升多镜像扫描效率

### 4.2 文件类型过滤

```go
// plugins/go/veinmind-malicious/scanner/malicious/scan.go:78-123
l.Walk("/", func(path string, info fs.FileInfo, err error) error {
    // 跳过特殊文件类型
    if (info.Mode() & (os.ModeDevice | os.ModeNamedPipe |
        os.ModeSocket | os.ModeCharDevice | os.ModeDir)) != 0 {
        return nil
    }

    // 忽略软链接
    if (info.Mode() & os.ModeSymlink) != 0 {
        return nil
    }

    f, err := l.Open(path)
    if err != nil {
        return nil
    }
    defer f.Close()

    // 仅扫描 ELF 文件
    _, err = elf.NewFile(f)
    if _, ok := err.(*elf.FormatError); ok {
        log.Debug("Skip File: ", path)
        return nil
    }

    // 执行扫描...
})
```

**过滤规则**:
- 跳过设备文件、管道、Socket、目录
- 跳过软链接（最终会扫描到实际文件）
- 仅扫描 ELF 可执行文件

### 4.3 双引擎并行扫描

```go
// plugins/go/veinmind-malicious/scanner/malicious/scan.go:125-151
var results []av.ScanResult

// 使用 ClamAV 进行扫描
if clamav.Active() {
    results, err = clamav.ScanStream(f)
    if err != nil {
        if _, ok := err.(*net.OpError); ok {
            log.Error(err)
        }
    }
}

// 使用 VirusTotal 进行扫描
fileByte, _ := io.ReadAll(f)
hash := sha256.New()
fileSha256 := hex.EncodeToString(hash.Sum(fileByte))

virustotalContext, _ := context.WithTimeout(context.Background(), 10*time.Millisecond)
if virustotal.Active() {
    vtResults, err := virustotal.ScanSHA256(virustotalContext, fileSha256)
    if err == nil && vtResults != nil && len(vtResults) > 0 {
        results = append(results, vtResults...)
    }
}
```

---

## 5. 数据持久化

### 5.1 数据模型

```go
// plugins/go/veinmind-malicious/database/model/model.go:7-47
type MaliciousFileInfo struct {
    gorm.Model
    Engine       string  // 检测引擎
    ImageID      string  // 镜像 ID
    LayerID      string  // Layer ID
    RelativePath string  // 相对路径
    FileName     string  // 文件名
    FileSize     string  // 文件大小
    FileMd5      string  // MD5 哈希
    FileSha256   string  // SHA256 哈希
    FileCreated  string  // 创建时间
    Description  string  // 恶意描述
}

type ReportImage struct {
    gorm.Model
    ImageName          string
    ImageID            string
    MaliciousFileCount int64
    ScanFileCount      int
    ImageCreatedAt     string
    MaliciousFileInfos []MaliciousFileInfo `gorm:"foreignKey:ImageID;references:ImageID"`
    Layers             []ReportLayer       `gorm:"foreignKey:ImageID;references:ImageID"`
}

type ReportLayer struct {
    gorm.Model
    ImageID            string
    LayerID            string
    MaliciousFileInfos []MaliciousFileInfo `gorm:"foreignKey:LayerID;references:LayerID"`
}
```

### 5.2 SQLite 单例数据库

```go
// plugins/go/veinmind-malicious/database/database.go:19-42
var instance *gorm.DB
var once sync.Once

func GetDbInstance() *gorm.DB {
    once.Do(func() {
        databasePath := os.Getenv("DATABASE_PATH")
        wd, _ := os.Getwd()
        databasePath = path.Join(wd, databasePath)

        // 确保目录存在
        databasePathDir := path.Dir(databasePath)
        if _, err := os.Stat(databasePathDir); os.IsNotExist(err) {
            os.Mkdir(databasePathDir, 0755)
        }

        instance, _ = gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
    })

    return instance
}
```

**特点**:
- 使用 `sync.Once` 保证单例
- 自动创建数据库目录
- 自动迁移表结构

---

## 6. 检测流程

```
┌─────────────────────────────────────────────────────────┐
│                  恶意文件扫描流程                         │
├─────────────────────────────────────────────────────────┤
│  1. 镜像级缓存检查                                       │
│     └─ 已扫描则直接返回结果                              │
├─────────────────────────────────────────────────────────┤
│  2. 遍历 Docker 镜像 Layers                             │
│     ├─ Layer 级缓存检查                                 │
│     │   └─ 已扫描则复用结果                             │
│     └─ 新 Layer 执行扫描                                │
├─────────────────────────────────────────────────────────┤
│  3. 遍历 Layer 内文件                                   │
│     ├─ 跳过特殊文件类型                                 │
│     ├─ 跳过非 ELF 文件                                  │
│     └─ 执行双引擎扫描                                   │
├─────────────────────────────────────────────────────────┤
│  4. 双引擎检测                                          │
│     ├─ ClamAV 流式扫描                                  │
│     └─ VirusTotal SHA256 查询                           │
├─────────────────────────────────────────────────────────┤
│  5. 结果合并与存储                                       │
│     ├─ 合并多引擎检测结果                               │
│     └─ 持久化到 SQLite                                  │
└─────────────────────────────────────────────────────────┘
```

---

## 7. 引擎对比

| 特性 | ClamAV | VirusTotal |
|------|--------|------------|
| 检测方式 | 流式扫描 | SHA256 哈希查询 |
| 部署要求 | 本地服务 | 仅需 API Key |
| 检测速度 | 快 | 受网络影响 |
| 病毒库 | 本地更新 | 云端多引擎 |
| 适用场景 | 离线环境 | 联网环境 |

---

## 8. 配置说明

| 环境变量 | 说明 | 示例 |
|---------|------|------|
| CLAMD_HOST | ClamAV 服务地址 | `127.0.0.1` |
| CLAMD_PORT | ClamAV 服务端口 | `3310` |
| VT_API_KEY | VirusTotal API Key | `your-api-key` |
| DATABASE_PATH | SQLite 数据库路径 | `./data/malicious.db` |

---

*文档生成时间: 2026-01-20*
