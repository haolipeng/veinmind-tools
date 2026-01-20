# veinmind-webshell Webshell 检测插件技术分析

**功能概述**: 检测容器和镜像中的 Webshell 脚本文件。

**代码位置**: `plugins/go/veinmind-webshell/`

---

## 1. 核心架构

采用云端检测服务 + 本地过滤的混合架构：

```go
// plugins/go/veinmind-webshell/pkg/detect/detect.go:36-41
type Kit struct {
    ctx    context.Context
    token  string           // API Token
    client *http.Client     // HTTP 客户端
}
```

---

## 2. 脚本类型过滤

### 2.1 支持的脚本类型

```go
// plugins/go/veinmind-webshell/pkg/filter/consts.go:5-18
type ScriptSuffix string

const (
    PHP_SUFFIX ScriptSuffix = ".php"
    JSP_SUFFIX ScriptSuffix = ".jsp"
    ASP_SUFFIX ScriptSuffix = ".asp"
)

type ScriptType string

const (
    UNKNOWN_TYPE            = "UNKNOWN"
    PHP_TYPE     ScriptType = "php"
    JSP_TYPE     ScriptType = "jsp"
    ASP_TYPE     ScriptType = "asp"
)
```

### 2.2 后缀映射表

```go
// plugins/go/veinmind-webshell/pkg/filter/consts.go:20-34
var scriptSuffixes []ScriptSuffix = []ScriptSuffix{
    PHP_SUFFIX,
    JSP_SUFFIX,
    ASP_SUFFIX,
}

var scriptSuffixTypeMap map[ScriptSuffix]ScriptType = map[ScriptSuffix]ScriptType{
    PHP_SUFFIX: PHP_TYPE,
    JSP_SUFFIX: JSP_TYPE,
    ASP_SUFFIX: ASP_TYPE,
}
```

### 2.3 过滤器实现

```go
// plugins/go/veinmind-webshell/pkg/filter/filter.go:10-23
var Kit *kit

type kit struct{}

// Filter indicates whether the file is a web script
func (f kit) Filter(path string, info fs.FileInfo) (bool, ScriptType, error) {
    for _, suffix := range scriptSuffixes {
        if suffix.Match(info.Name()) {
            if t, ok := scriptSuffixTypeMap[suffix]; ok {
                return true, t, nil
            }
        }
    }
    return false, UNKNOWN_TYPE, nil
}
```

---

## 3. 云端检测服务

### 3.1 检测服务配置

```go
// plugins/go/veinmind-webshell/pkg/detect/consts.go:3-4
const token = "API_TOKEN"
const url = "https://guanshan.rivers.chaitin.cn/api/v1/detect"
```

**说明**: 使用长亭科技的关山云端 Webshell 检测服务。

### 3.2 检测 Kit 初始化

```go
// plugins/go/veinmind-webshell/pkg/detect/detect.go:71-79
func NewKit(ctx context.Context, opts ...KitOption) (*Kit, error) {
    k := new(Kit)
    k.ctx = ctx

    for _, opt := range opts {
        opt(k)
    }
    return k, nil
}
```

### 3.3 函数式选项模式

```go
// plugins/go/veinmind-webshell/pkg/detect/detect.go:44-69
type KitOption func(kit *Kit)

func WithToken(token string) KitOption {
    return func(kit *Kit) {
        kit.token = token
    }
}

func WithDefaultToken() KitOption {
    return func(kit *Kit) {
        kit.token = token
    }
}

func WithClient(client *http.Client) KitOption {
    return func(kit *Kit) {
        kit.client = client
    }
}

func WithDefaultClient() KitOption {
    return func(kit *Kit) {
        tr := &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }
        kit.client = &http.Client{Transport: tr}
    }
}
```

---

## 4. 检测实现

### 4.1 文件信息结构

```go
// plugins/go/veinmind-webshell/pkg/detect/detect.go:17-23
type FileInfo struct {
    Path        string           // 文件路径
    Reader      io.Reader        // 文件内容读取器
    RawFileInfo fs.FileInfo      // 原始文件信息
    ScriptType  filter.ScriptType // 脚本类型
}
```

### 4.2 检测结果结构

```go
// plugins/go/veinmind-webshell/pkg/detect/detect.go:25-34
type Result struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Data    struct {
        RiskLevel int    `json:"risk_level"`  // 风险等级
        ID        string `json:"id"`          // 检测 ID
        Type      string `json:"type"`        // Webshell 类型
        Reason    string `json:"reason"`      // 检测原因
        Engine    string `json:"engine"`      // 检测引擎
    } `json:"data"`
}
```

### 4.3 云端检测调用

```go
// plugins/go/veinmind-webshell/pkg/detect/detect.go:81-130
func (k *Kit) Detect(info FileInfo) (*Result, error) {
    buf := new(bytes.Buffer)
    writer := multipart.NewWriter(buf)

    // 创建文件表单字段
    part, err := writer.CreateFormFile("file", info.Path)
    if err != nil {
        return nil, err
    }

    // 写入文件内容
    _, err = io.Copy(part, info.Reader)
    if err != nil {
        return nil, err
    }

    // 添加元数据字段
    _ = writer.WriteField("tag", "veinmind-webshell")
    _ = writer.WriteField("type", info.ScriptType.String())

    err = writer.Close()
    if err != nil {
        return nil, err
    }

    // 构建 HTTP 请求
    req, err := http.NewRequest("POST", url, buf)
    if err != nil {
        return nil, err
    }

    req.Header.Add("X-Ca-Token", k.token)
    req.Header.Add("Content-Type", writer.FormDataContentType())

    // 发送请求
    resp, err := k.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // 解析响应
    body, _ := ioutil.ReadAll(resp.Body)

    res := &Result{}
    err = json.Unmarshal(body, res)
    if err != nil {
        return nil, err
    }

    return res, nil
}
```

---

## 5. 并发扫描实现

### 5.1 errgroup 并发控制

```go
// plugins/go/veinmind-webshell/cmd/webshell/cmd.go:38-97
func scanImage(c *cmd.Command, image api.Image) (err error) {
    detectKit, err := detect.NewKit(context.Background(),
        detect.WithToken(token),
        detect.WithDefaultClient())
    if err != nil {
        return err
    }

    // Error group for detect kit
    errG := errgroup.Group{}
    errG.SetLimit(100)  // 最大 100 个并发

    err = image.Walk("/", func(path string, info fs.FileInfo, err error) error {
        // 过滤非脚本文件
        if isScript, scriptType, err := filter.Kit.Filter(path, info); !isScript {
            return nil
        } else {
            if err != nil {
                log.Error(err)
                return nil
            }

            // 提交异步检测任务
            errG.Go(func() error {
                f, err := image.Open(path)
                if err != nil {
                    log.Error(err)
                    return nil
                }

                detectFileInfo := detect.FileInfo{
                    Path:        path,
                    Reader:      f,
                    ScriptType:  scriptType,
                    RawFileInfo: info,
                }

                // 调用云端检测
                res, err := detectKit.Detect(detectFileInfo)
                if err != nil {
                    log.Error(err)
                    return nil
                }

                // 转换并上报事件
                evt, err := detect.Convert2ReportEvent(image, detectFileInfo, *res)
                if err != nil {
                    log.Error(err)
                    return nil
                }
                if evt != nil {
                    reportService.Client.Report(evt)
                }
                return nil
            })

            return nil
        }
    })

    errG.Wait()

    return err
}
```

### 5.2 容器扫描（类似实现）

```go
// plugins/go/veinmind-webshell/cmd/webshell/cmd.go:99-158
func scanContainer(c *cmd.Command, container api.Container) (err error) {
    detectKit, err := detect.NewKit(context.Background(),
        detect.WithToken(token),
        detect.WithDefaultClient())
    if err != nil {
        return err
    }

    errG := errgroup.Group{}
    errG.SetLimit(100)

    err = container.Walk("/", func(path string, info fs.FileInfo, err error) error {
        // 过滤和检测逻辑与 scanImage 类似
        // ...
    })

    errG.Wait()

    return err
}
```

---

## 6. 命令行接口

```go
// plugins/go/veinmind-webshell/cmd/webshell/cmd.go:160-171
func init() {
    rootCommand.AddCommand(scanCommand)
    rootCommand.AddCommand(cmd.NewInfoCommand(plugin.Manifest{
        Name:        "veinmind-webshell",
        Author:      "veinmind-team",
        Description: "veinmind-webshell scan image webshell data",
    }))

    scanCommand.AddCommand(report.MapReportCmd(
        cmd.MapImageCommand(scanImageCommand, scanImage), reportService))
    scanCommand.AddCommand(report.MapReportCmd(
        cmd.MapContainerCommand(scanContainerCommand, scanContainer), reportService))

    // Token 参数
    scanCommand.PersistentFlags().StringVarP(&token, "token", "t", "", "百川 api token")
}
```

---

## 7. 检测流程

```
┌─────────────────────────────────────────────────────────┐
│                  Webshell 检测流程                       │
├─────────────────────────────────────────────────────────┤
│  1. 遍历文件系统                                         │
│     └─ image.Walk("/") 或 container.Walk("/")           │
├─────────────────────────────────────────────────────────┤
│  2. 脚本类型过滤                                         │
│     ├─ 匹配后缀: .php, .jsp, .asp                       │
│     └─ 非脚本文件跳过                                    │
├─────────────────────────────────────────────────────────┤
│  3. 提交并发检测任务                                     │
│     ├─ errgroup.SetLimit(100)                           │
│     └─ 异步提交到云端检测                                │
├─────────────────────────────────────────────────────────┤
│  4. 云端检测                                             │
│     ├─ 上传文件内容 (multipart/form-data)               │
│     ├─ 携带脚本类型标识                                  │
│     └─ 获取检测结果                                      │
├─────────────────────────────────────────────────────────┤
│  5. 结果上报                                             │
│     ├─ 转换为统一事件格式                                │
│     └─ 上报到报告服务                                    │
└─────────────────────────────────────────────────────────┘
```

---

## 8. 支持的 Webshell 类型

| 类型 | 后缀 | 说明 |
|------|------|------|
| PHP | .php | PHP 脚本木马 |
| JSP | .jsp | Java Server Pages 木马 |
| ASP | .asp | Active Server Pages 木马 |

---

## 9. 设计亮点

### 9.1 函数式选项模式

```go
detectKit, err := detect.NewKit(
    context.Background(),
    detect.WithToken(token),       // 可选: 自定义 Token
    detect.WithDefaultClient(),    // 可选: 默认 HTTP 客户端
)
```

**优势**:
- 灵活配置
- 向后兼容
- 清晰的 API 设计

### 9.2 errgroup 并发控制

```go
errG := errgroup.Group{}
errG.SetLimit(100)  // 最大 100 并发

errG.Go(func() error {
    // 检测任务
    return nil
})

errG.Wait()  // 等待所有任务完成
```

**优势**:
- 简洁的并发控制
- 自动错误收集
- 可配置并发上限

### 9.3 云端检测架构

```
┌─────────────┐     HTTP POST     ┌──────────────────┐
│  veinmind   │ ──────────────────> │  关山云检测服务  │
│  webshell   │ <────────────────── │  (长亭科技)      │
└─────────────┘      JSON Result   └──────────────────┘
```

**优势**:
- 无需维护本地规则库
- 实时更新检测能力
- 减少本地计算资源消耗

---

## 10. 配置说明

| 参数 | 说明 | 示例 |
|------|------|------|
| -t, --token | 云端检测 API Token | `your-api-token` |

---

*文档生成时间: 2026-01-20*
