# Veinmind Go 插件指南

本文档详细介绍 veinmind-tools 中所有 Go 插件的功能、实现原理和使用方法。

## 目录

- [概述](#概述)
- [插件列表](#插件列表)
- [通用架构模式](#通用架构模式)
- [插件详细介绍](#插件详细介绍)
  - [1. veinmind-backdoor](#1-veinmind-backdoor)
  - [2. veinmind-basic](#2-veinmind-basic)
  - [3. veinmind-escape](#3-veinmind-escape)
  - [4. veinmind-iac](#4-veinmind-iac)
  - [5. veinmind-log4j2](#5-veinmind-log4j2)
  - [6. veinmind-malicious](#6-veinmind-malicious)
  - [7. veinmind-minio](#7-veinmind-minio)
  - [8. veinmind-privilege-escalation](#8-veinmind-privilege-escalation)
  - [9. veinmind-sensitive](#9-veinmind-sensitive)
  - [10. veinmind-trace](#10-veinmind-trace)
  - [11. veinmind-unsafe-mount](#11-veinmind-unsafe-mount)
  - [12. veinmind-vuln](#12-veinmind-vuln)
  - [13. veinmind-weakpass](#13-veinmind-weakpass)
  - [14. veinmind-webshell](#14-veinmind-webshell)
- [插件对比表](#插件对比表)
- [核心依赖库](#核心依赖库)

---

## 概述

Veinmind-tools 是长亭科技开发的容器安全工具集，包含 14 个 Go 语言编写的安全扫描插件。这些插件覆盖了容器安全的各个方面，包括：

- **后门检测** - 检测容器/镜像中的后门程序
- **漏洞扫描** - 识别已知 CVE 漏洞
- **敏感信息** - 发现泄露的凭证和敏感数据
- **配置审计** - 检查不安全的配置和权限
- **恶意软件** - 使用杀毒引擎扫描恶意文件
- **运行时安全** - 监控容器运行时行为

所有插件基于 `libveinmind` 核心库构建，共享统一的命令行接口和报告格式。

---

## 插件列表

| 序号 | 插件名称 | 功能简述 |
|------|----------|----------|
| 1 | veinmind-backdoor | 后门检测扫描器 |
| 2 | veinmind-basic | 镜像/容器基础信息收集 |
| 3 | veinmind-escape | 容器逃逸风险检测 |
| 4 | veinmind-iac | IaC 配置安全扫描 |
| 5 | veinmind-log4j2 | Log4j2 漏洞检测 |
| 6 | veinmind-malicious | 恶意文件扫描 |
| 7 | veinmind-minio | MinIO CVE 检测 |
| 8 | veinmind-privilege-escalation | 提权风险检测 |
| 9 | veinmind-sensitive | 敏感信息扫描 |
| 10 | veinmind-trace | 运行时安全检测 |
| 11 | veinmind-unsafe-mount | 不安全挂载检测 |
| 12 | veinmind-vuln | 漏洞和资产扫描 |
| 13 | veinmind-weakpass | 弱密码检测 |
| 14 | veinmind-webshell | Webshell 检测 |

---

## 通用架构模式

所有 Go 插件遵循一致的架构设计：

### 命令结构
```
根命令 → scan 子命令 → 目标类型（image/container）
```

### 核心接口

```go
// 插件注册使用 libveinmind 提供的命令框架
import (
    api "github.com/chaitin/libveinmind/go"
    "github.com/chaitin/libveinmind/go/cmd"
    "github.com/chaitin/libveinmind/go/plugin"
)

// 典型的扫描命令结构
var scanImageCmd = &cmd.Command{
    Use:   "image",
    Short: "扫描容器镜像",
    RunE: func(cmd *cmd.Command, args []string) error {
        return cmd.ScanImage(args, scanImage)
    },
}

// 扫描回调函数
func scanImage(image api.Image) error {
    // 遍历文件系统
    image.Walk("/", func(path string, info os.FileInfo, err error) error {
        // 检测逻辑
        return nil
    })
    return nil
}
```

### 报告机制

所有插件使用 `veinmind-common-go` 提供的统一报告服务：

```go
import "github.com/chaitin/veinmind-common-go/service/report"

// 创建事件
event := report.ReportEvent{
    ID:         "rule-id",
    Level:      "High",
    DetectType: report.Image,
    AlertType:  report.Asset,
    EventType:  report.Risk,
    AlertDetails: []report.AlertDetail{
        {
            BackdoorDetail: &report.BackdoorDetail{
                FileDetail: report.FileDetail{Path: filePath},
                Description: "检测到后门",
            },
        },
    },
}

// 发送报告
report.DefaultService().Report(event)
```

### 文件系统访问

```go
// 遍历镜像文件系统
image.Walk("/", walkFunc)

// 遍历容器文件系统
container.Walk("/", walkFunc)

// 读取单个文件
file, err := image.Open("/etc/passwd")
```

### 输出格式

所有插件支持以下输出格式：
- **CLI** - 命令行表格输出
- **JSON** - 结构化 JSON 格式
- **HTML** - 网页报告格式

---

## 插件详细介绍

### 1. veinmind-backdoor

**位置:** `plugins/go/veinmind-backdoor/`

#### 功能说明

容器/镜像后门检测扫描器，快速扫描容器镜像和运行容器中的后门风险。

#### 检测模块

| 模块名 | 检测内容 |
|--------|----------|
| bashrc | bash 启动脚本后门 |
| preload | 动态链接库后门 |
| PROMPT_COMMAND | PROMPT_COMMAND 环境变量后门 |
| cron | 定时任务后门 |
| ldsopreload | ld.so.preload 预加载后门 |
| inetd | inetd 配置文件后门 |
| xinetd | xinetd 配置文件后门 |
| sshd | SSHD 软链接后门 |
| startup | 系统启动项后门 |
| tcpWrapper | TCP Wrapper 后门 |
| sshWrapper | SSH Wrapper 后门 |
| rootkit | Rootkit 后门检测 |

#### 实现原理

```go
// 检测函数注册表
var CheckFuncMap = map[string]CheckFunc{
    "bashrc":    CheckBashrc,
    "preload":   CheckPreload,
    "cron":      CheckCron,
    // ...
}

// 使用 Walk 遍历文件系统
image.Walk("/", func(path string, info os.FileInfo, err error) error {
    // 根据路径匹配检测规则
    for name, checkFunc := range CheckFuncMap {
        if matchPath(path, name) {
            result := checkFunc(image, path, info)
            if result.IsBackdoor {
                report(result)
            }
        }
    }
    return nil
})
```

#### 扫描目标

- Docker 镜像
- 运行中的容器
- 停止的容器

---

### 2. veinmind-basic

**位置:** `plugins/go/veinmind-basic/`

#### 功能说明

镜像/容器详细信息收集器，提取全面的元数据信息。

#### 收集的信息

**镜像信息：**
- 创建时间
- 环境变量
- 入口点 (Entrypoint)
- 默认命令 (Cmd)
- 工作目录
- 暴露端口
- 标签

**容器信息：**
- 运行时类型 (Docker/Containerd)
- 进程列表
- 挂载点
- 用户/组映射
- 能力 (Capabilities)

#### 实现原理

```go
// 获取 OCI 规范信息
func scanImage(image api.Image) error {
    // 获取镜像 OCI 规范
    ociSpec, err := image.OCISpecV1()
    if err != nil {
        return err
    }

    // 提取配置信息
    config := ociSpec.Config
    envVars := config.Env
    entrypoint := config.Entrypoint
    cmd := config.Cmd

    // 生成资产报告
    return reportAsset(image, ociSpec)
}

func scanContainer(container api.Container) error {
    // 获取容器 OCI 规范
    ociSpec, err := container.OCISpec()

    // 获取进程列表
    pids, _ := container.Pids()
    for _, pid := range pids {
        proc, _ := container.NewProcess(pid)
        // 收集进程信息
    }

    // 解析用户名映射
    passwdFile := passwd.ParseFilesystemPasswd(container)

    return nil
}
```

#### 核心依赖

- `github.com/opencontainers/runtime-spec/specs-go` - OCI 规范定义

---

### 3. veinmind-escape

**位置:** `plugins/go/veinmind-escape/`

#### 功能说明

容器逃逸风险检测扫描器，识别可能导致容器逃逸的漏洞和配置。

#### 检测模块

| 模块 | 检测内容 |
|------|----------|
| CVE 检测 | 内核版本漏洞匹配 |
| Mount 检查 | 危险挂载点配置 |
| Privilege 检查 | 特权提升向量 |
| Docker API | Docker Socket 暴露 |
| Sudo 检查 | sudo 配置错误 |

#### 实现原理

```go
// CVE 版本规则定义 (TOML 格式)
type CVERule struct {
    CVE         string   `toml:"cve"`
    Description string   `toml:"description"`
    MinVersion  string   `toml:"min_version"`
    MaxVersion  string   `toml:"max_version"`
    FixedIn     []string `toml:"fixed_in"`
}

// 内核版本检查
func checkKernelCVE(container api.Container) []EscapeRisk {
    kernelVersion := getKernelVersion()

    for _, rule := range cveRules {
        if versionInRange(kernelVersion, rule.MinVersion, rule.MaxVersion) {
            if !containsVersion(rule.FixedIn, kernelVersion) {
                risks = append(risks, EscapeRisk{
                    CVE:         rule.CVE,
                    Description: rule.Description,
                })
            }
        }
    }
    return risks
}

// 挂载点检查
func checkMounts(container api.Container) []EscapeRisk {
    spec, _ := container.OCISpec()
    for _, mount := range spec.Mounts {
        if isDangerousMount(mount.Source) {
            // 如 /var/run/docker.sock
            risks = append(risks, EscapeRisk{
                Type: "dangerous_mount",
                Path: mount.Source,
            })
        }
    }
    return risks
}
```

#### 规则文件

规则定义在 TOML 文件中，支持自定义：

```toml
[[cve]]
cve = "CVE-2022-0847"
description = "Dirty Pipe 漏洞"
min_version = "5.8"
max_version = "5.16.11"
fixed_in = ["5.16.11", "5.15.25", "5.10.102"]
```

---

### 4. veinmind-iac

**位置:** `plugins/go/veinmind-iac/`

#### 功能说明

Infrastructure as Code (IaC) 安全扫描器，检测 Dockerfile 和 Kubernetes 配置中的安全风险。

#### 支持的文件类型

- Dockerfile
- Kubernetes YAML 清单

#### 检测规则示例

**Dockerfile 规则：**
- 使用 root 用户运行
- 敏感信息硬编码
- 使用不安全的基础镜像
- ADD 代替 COPY
- 未固定依赖版本

**Kubernetes 规则：**
- 特权容器
- hostNetwork 启用
- 敏感路径挂载
- 缺少资源限制
- 不安全的 securityContext

#### 实现原理

```go
import (
    "github.com/open-policy-agent/opa/rego"
    "github.com/moby/buildkit/frontend/dockerfile/parser"
)

// 使用 OPA 策略引擎评估
func scanIaC(filePath string) ([]Violation, error) {
    content, _ := os.ReadFile(filePath)

    // 解析 Dockerfile
    if isDockerfile(filePath) {
        ast, _ := parser.Parse(bytes.NewReader(content))
        return evaluateDockerfile(ast)
    }

    // 解析 Kubernetes YAML
    if isKubernetesYAML(filePath) {
        return evaluateKubernetes(content)
    }

    return nil, nil
}

// OPA Rego 策略评估
func evaluatePolicy(input interface{}, policy string) ([]Violation, error) {
    ctx := context.Background()
    query, _ := rego.New(
        rego.Query("data.brightMirror.violations"),
        rego.Module("policy.rego", policy),
    ).PrepareForEval(ctx)

    results, _ := query.Eval(ctx, rego.EvalInput(input))
    return parseViolations(results)
}
```

#### 核心依赖

- `github.com/open-policy-agent/opa` - 策略引擎
- `github.com/moby/buildkit` - Dockerfile 解析

---

### 5. veinmind-log4j2

**位置:** `plugins/go/veinmind-log4j2/`

#### 功能说明

专门检测 CVE-2021-44228 (Log4j2 JNDI RCE) 漏洞的扫描器。

#### 漏洞范围

- Log4j2 2.0-beta9 至 2.15.0
- 排除安全版本：2.12.2, 2.12.3, 2.3.1

#### 检测方法

1. 扫描 `.jar` 和 `.war` 文件
2. 解压 jar 包检查内容
3. 搜索漏洞类文件
4. 支持嵌套 jar 检测

#### 实现原理

```go
import "archive/zip"

// 漏洞类文件
var vulnerableClasses = []string{
    "org/apache/logging/log4j/core/lookup/JndiLookup.class",
    "org/apache/logging/log4j/core/net/JndiManager.class",
}

func scanJar(image api.Image, jarPath string, depth int) error {
    // 限制嵌套深度防止无限递归
    if depth > maxDepth {
        return nil
    }

    file, _ := image.Open(jarPath)
    zipReader, _ := zip.NewReader(file, fileSize)

    for _, f := range zipReader.File {
        // 检查漏洞类文件
        if isVulnerableClass(f.Name) {
            reportVulnerability(jarPath, f.Name)
        }

        // 递归检查嵌套 jar
        if strings.HasSuffix(f.Name, ".jar") {
            scanNestedJar(f, depth+1)
        }
    }
    return nil
}

func isVulnerable(version string) bool {
    // 版本比较逻辑
    if version >= "2.0-beta9" && version <= "2.15.0" {
        if version == "2.12.2" || version == "2.12.3" || version == "2.3.1" {
            return false // 已修复版本
        }
        return true
    }
    return false
}
```

---

### 6. veinmind-malicious

**位置:** `plugins/go/veinmind-malicious/`

#### 功能说明

恶意文件扫描器，使用 ClamAV 和 VirusTotal 进行综合恶意软件检测。

#### 扫描引擎

| 引擎 | 说明 |
|------|------|
| ClamAV | 本地杀毒引擎 |
| VirusTotal | 云端多引擎检测 |

#### 实现原理

```go
import (
    "github.com/testwill/go-clamd"
    "github.com/VirusTotal/vt-go"
)

// ClamAV 扫描
func scanWithClamAV(filePath string) (*ScanResult, error) {
    clam := clamd.NewClamd("tcp://localhost:3310")
    response, _ := clam.ScanFile(filePath)

    for result := range response {
        if result.Status == "FOUND" {
            return &ScanResult{
                Malware:   true,
                Signature: result.Description,
            }, nil
        }
    }
    return &ScanResult{Malware: false}, nil
}

// VirusTotal 扫描
func scanWithVirusTotal(filePath string) (*ScanResult, error) {
    client := vt.NewClient(apiKey)

    // 计算文件哈希
    hash := sha256sum(filePath)

    // 查询已有结果
    file, _ := client.GetObject(vt.URL("files/%s", hash))

    stats := file.Get("last_analysis_stats")
    if stats.GetInt64("malicious") > 0 {
        return &ScanResult{
            Malware:    true,
            Detections: stats.GetInt64("malicious"),
        }, nil
    }

    return &ScanResult{Malware: false}, nil
}
```

#### 层级扫描

```go
// 按镜像层扫描，优化性能
func scanImageLayers(image api.Image) error {
    layers, _ := image.Layers()

    for _, layer := range layers {
        layerReader, _ := layer.Uncompressed()
        tarReader := tar.NewReader(layerReader)

        for {
            header, err := tarReader.Next()
            if err == io.EOF {
                break
            }

            if header.Typeflag == tar.TypeReg {
                scanFile(header.Name, tarReader)
            }
        }
    }
    return nil
}
```

#### 核心依赖

- `github.com/testwill/go-clamd` - ClamAV 客户端
- `github.com/VirusTotal/vt-go` - VirusTotal API
- `gorm.io/gorm` - 数据库 ORM

---

### 7. veinmind-minio

**位置:** `plugins/go/veinmind-minio/`

#### 功能说明

专门检测 CVE-2023-28432 (MinIO 信息泄露) 漏洞的扫描器。

#### 漏洞范围

```
RELEASE.2019-12-17T23-16-33Z 至 RELEASE.2023-03-20T20-16-18Z
```

#### 实现原理

```go
import "regexp"

// 版本正则匹配
var versionPattern = regexp.MustCompile(
    `RELEASE\.(\d{4}-\d{2}-\d{2})T(\d{2}-\d{2}-\d{2})Z`,
)

func scanMinio(image api.Image) error {
    // 查找 minio 二进制文件
    image.Walk("/", func(path string, info os.FileInfo, err error) error {
        if filepath.Base(path) == "minio" && info.Mode().IsRegular() {
            version := extractVersion(image, path)
            if isVulnerable(version) {
                reportVulnerability(path, version)
            }
        }
        return nil
    })
    return nil
}

func extractVersion(image api.Image, path string) string {
    content, _ := image.ReadFile(path)
    matches := versionPattern.FindSubmatch(content)
    if matches != nil {
        return string(matches[0])
    }
    return ""
}

func isVulnerable(version string) bool {
    releaseDate := parseReleaseDate(version)
    startDate := time.Date(2019, 12, 17, 0, 0, 0, 0, time.UTC)
    endDate := time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC)

    return releaseDate.After(startDate) && releaseDate.Before(endDate)
}
```

---

### 8. veinmind-privilege-escalation

**位置:** `plugins/go/veinmind-privilege-escalation/`

#### 功能说明

基于 GTFOBins 方法论的提权风险检测扫描器。

#### 检测模块

| 模块 | 检测内容 |
|------|----------|
| SUID | SUID 位二进制检测 |
| Limited SUID | 受限 SUID 二进制 |
| Sudo | sudo 配置问题 |
| Capabilities | Linux 能力提权 |

#### 扫描路径

- `/bin`
- `/sbin`
- `/usr/bin`
- `/usr/sbin`
- `/usr/local/bin`
- `/usr/local/sbin`

#### 实现原理

```go
// 规则结构 (TOML)
type PrivescRule struct {
    Binary      string   `toml:"binary"`
    Tags        []string `toml:"tags"` // suid, sudo, capabilities
    Exp         string   `toml:"exp"`  // 利用方法
    Description string   `toml:"description"`
}

// 加载规则
var rules []PrivescRule

func init() {
    // 从嵌入的 TOML 文件加载规则
    toml.Unmarshal(embeddedRules, &rules)
}

func scanForSUID(image api.Image) []PrivescRisk {
    var risks []PrivescRisk

    for _, binPath := range binaryPaths {
        image.Walk(binPath, func(path string, info os.FileInfo, err error) error {
            // 检查 SUID 位
            if info.Mode()&os.ModeSetuid != 0 {
                binary := filepath.Base(path)

                // 匹配规则
                for _, rule := range rules {
                    if rule.Binary == binary && contains(rule.Tags, "suid") {
                        risks = append(risks, PrivescRisk{
                            Binary:      path,
                            Type:        "SUID",
                            Exp:         rule.Exp,
                            Description: rule.Description,
                        })
                    }
                }
            }
            return nil
        })
    }
    return risks
}
```

#### GTFOBins 规则示例

```toml
[[binary]]
name = "vim"
tags = ["suid", "sudo"]
exp = "vim -c ':!/bin/sh'"
description = "Vim 可用于提权获取 shell"

[[binary]]
name = "find"
tags = ["suid", "sudo"]
exp = "find . -exec /bin/sh \\; -quit"
description = "Find 可通过 -exec 参数执行命令"
```

---

### 9. veinmind-sensitive

**位置:** `plugins/go/veinmind-sensitive/`

#### 功能说明

敏感数据检测扫描器，使用可自定义的正则规则发现泄露的凭证和敏感信息。

#### 规则字段

| 字段 | 说明 |
|------|------|
| id | 规则标识符 |
| description | 规则描述 |
| match | 内容匹配正则 |
| filepath | 路径匹配正则 |
| env | 环境变量匹配 |

#### 检测类型

- API 密钥 (AWS, GCP, Azure 等)
- 数据库凭证
- SSH 私钥
- 证书文件
- 配置文件中的密码
- 环境变量中的敏感信息

#### 实现原理

```go
import (
    "github.com/BurntSushi/toml"
    "github.com/gabriel-vasile/mimetype"
)

// 规则定义
type SensitiveRule struct {
    ID          string `toml:"id"`
    Description string `toml:"description"`
    Match       string `toml:"match"`    // 内容正则
    Filepath    string `toml:"filepath"` // 路径正则
    Env         string `toml:"env"`      // 环境变量正则
}

func scanForSensitive(image api.Image) error {
    rules := loadRules()

    // 扫描环境变量
    ociSpec, _ := image.OCISpecV1()
    for _, env := range ociSpec.Config.Env {
        for _, rule := range rules {
            if rule.Env != "" {
                re := regexp.MustCompile("(?i)" + rule.Env) // 忽略大小写
                if re.MatchString(env) {
                    reportSensitive(rule, "env", env)
                }
            }
        }
    }

    // 扫描文件内容
    image.Walk("/", func(path string, info os.FileInfo, err error) error {
        // 路径匹配
        for _, rule := range rules {
            if rule.Filepath != "" {
                if regexp.MustCompile(rule.Filepath).MatchString(path) {
                    reportSensitive(rule, "filepath", path)
                }
            }
        }

        // 内容匹配
        if info.Mode().IsRegular() && info.Size() < maxFileSize {
            // 检查 MIME 类型
            mime := mimetype.Detect(path)
            if isTextType(mime) {
                content, _ := image.ReadFile(path)
                for _, rule := range rules {
                    if rule.Match != "" {
                        if regexp.MustCompile(rule.Match).Match(content) {
                            reportSensitive(rule, "content", path)
                        }
                    }
                }
            }
        }
        return nil
    })

    return nil
}
```

#### 规则示例

```toml
[[rule]]
id = "aws-access-key"
description = "AWS Access Key ID"
match = "AKIA[0-9A-Z]{16}"

[[rule]]
id = "ssh-private-key"
description = "SSH 私钥文件"
filepath = "id_rsa|id_dsa|id_ecdsa|id_ed25519"
match = "-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"

[[rule]]
id = "password-in-env"
description = "环境变量中的密码"
env = "(password|passwd|pwd)=.+"
```

#### 核心依赖

- `github.com/BurntSushi/toml` - 配置解析
- `github.com/gabriel-vasile/mimetype` - MIME 类型检测
- `golang.org/x/sync` - 并发控制

---

### 10. veinmind-trace

**位置:** `plugins/go/veinmind-trace/`

#### 功能说明

容器运行时安全检测器，识别异常行为和安全威胁。

#### 检测模块

| 模块 | 检测内容 |
|------|----------|
| 隐藏进程 | mount -o bind 隐藏技术 |
| 反弹 Shell | 反向 shell 进程 |
| 可疑进程 | 挖矿工具、黑客工具 |
| Ptrace 进程 | 调试器/追踪器进程 |
| 文件异常 | 敏感目录权限问题 |
| CDK 工具 | 容器逃逸工具痕迹 |
| 异常用户 | UID=0 非 root、重复 UID |

#### 分析器架构

```go
// 分析器接口
type Analyzer interface {
    Name() string
    Analyze(container api.Container) ([]TraceEvent, error)
}

// 分析器组
type AnalyzerGroup struct {
    analyzers []Analyzer
}

func (g *AnalyzerGroup) Register(a Analyzer) {
    g.analyzers = append(g.analyzers, a)
}

func (g *AnalyzerGroup) Analyze(container api.Container) []TraceEvent {
    var events []TraceEvent
    for _, analyzer := range g.analyzers {
        results, _ := analyzer.Analyze(container)
        events = append(events, results...)
    }
    return events
}
```

#### 实现原理

```go
// 进程分析器
type ProcessAnalyzer struct{}

func (a *ProcessAnalyzer) Analyze(container api.Container) ([]TraceEvent, error) {
    pids, _ := container.Pids()
    var events []TraceEvent

    for _, pid := range pids {
        proc, _ := container.NewProcess(pid)
        cmdline, _ := proc.Cmdline()

        // 检查隐藏进程
        if isHiddenProcess(proc) {
            events = append(events, TraceEvent{
                Type:    "hidden_process",
                PID:     pid,
                Cmdline: cmdline,
            })
        }

        // 检查反弹 shell
        if isReverseShell(cmdline) {
            events = append(events, TraceEvent{
                Type:    "reverse_shell",
                PID:     pid,
                Cmdline: cmdline,
            })
        }

        // 检查可疑进程名
        if isSuspiciousProcess(cmdline) {
            events = append(events, TraceEvent{
                Type:    "suspicious_process",
                PID:     pid,
                Cmdline: cmdline,
            })
        }
    }
    return events, nil
}

// 用户分析器
type UserAnalyzer struct{}

func (a *UserAnalyzer) Analyze(container api.Container) ([]TraceEvent, error) {
    passwdFile, _ := container.Open("/etc/passwd")
    users := passwd.Parse(passwdFile)

    var events []TraceEvent
    uidMap := make(map[int][]string)

    for _, user := range users {
        // 检测非 root 的 UID=0 用户
        if user.UID == 0 && user.Name != "root" {
            events = append(events, TraceEvent{
                Type:     "uid0_non_root",
                Username: user.Name,
            })
        }

        // 检测重复 UID
        uidMap[user.UID] = append(uidMap[user.UID], user.Name)
    }

    for uid, names := range uidMap {
        if len(names) > 1 {
            events = append(events, TraceEvent{
                Type: "duplicate_uid",
                UID:  uid,
                Users: names,
            })
        }
    }

    return events, nil
}
```

#### 扫描目标

- 仅运行中的容器 (Docker/Containerd)

---

### 11. veinmind-unsafe-mount

**位置:** `plugins/go/veinmind-unsafe-mount/`

#### 功能说明

容器不安全挂载检测扫描器，识别危险的卷绑定。

#### 危险挂载类型

| 挂载路径 | 风险等级 | 说明 |
|----------|----------|------|
| `/` | 严重 | 主机根目录 |
| `/etc` | 高 | 系统配置目录 |
| `/var/run/docker.sock` | 严重 | Docker API 访问 |
| `/proc` | 高 | 进程信息 |
| `/sys` | 高 | 内核参数 |

#### 实现原理

```go
// 危险挂载路径列表
var dangerousMounts = []string{
    "/",
    "/etc",
    "/root",
    "/var/run/docker.sock",
    "/proc",
    "/sys",
    "/dev",
}

func DetectContainerUnsafeMount(container api.Container) ([]UnsafeMount, error) {
    spec, _ := container.OCISpec()
    var unsafeMounts []UnsafeMount

    for _, mount := range spec.Mounts {
        // 检查源路径
        for _, dangerous := range dangerousMounts {
            if strings.HasPrefix(mount.Source, dangerous) {
                // 检查是否为读写模式
                isReadWrite := !containsOption(mount.Options, "ro")

                unsafeMounts = append(unsafeMounts, UnsafeMount{
                    Source:      mount.Source,
                    Destination: mount.Destination,
                    ReadWrite:   isReadWrite,
                    RiskLevel:   getRiskLevel(mount.Source),
                })
            }
        }
    }

    return unsafeMounts, nil
}
```

#### 扫描目标

- 仅运行中的容器

---

### 12. veinmind-vuln

**位置:** `plugins/go/veinmind-vuln/`

#### 功能说明

综合漏洞和资产扫描器，检测操作系统包、应用库和已知 CVE。

#### 扫描能力

| 类型 | 说明 |
|------|------|
| OS 检测 | Linux 发行版识别 |
| 包枚举 | 系统包管理器 |
| 库检测 | 应用级依赖 |
| 漏洞匹配 | CVE 数据库查询 |

#### 支持的包类型

- Python (pip)
- Node.js (npm)
- Java (jar)
- Ruby (gem)
- Go (go.mod)
- Rust (cargo)
- .NET (nuget)

#### 实现原理

```go
import (
    "github.com/aquasecurity/trivy/pkg/detector"
    "github.com/aquasecurity/go-dep-parser"
)

func scanForVulnerabilities(image api.Image) error {
    // OS 检测
    osInfo := detector.DetectOS(image)

    // 包枚举
    packages := detector.ListPackages(image, osInfo)

    // 应用依赖检测
    apps := detectApplications(image)

    // 漏洞匹配
    vulns := detector.Detect(packages, apps)

    for _, vuln := range vulns {
        reportVulnerability(vuln)
    }

    return nil
}

func detectApplications(image api.Image) []Application {
    var apps []Application

    // Python
    image.Walk("/", func(path string, info os.FileInfo, err error) error {
        if filepath.Base(path) == "requirements.txt" {
            deps := depparser.ParsePython(path)
            apps = append(apps, Application{Type: "python", Deps: deps})
        }

        if filepath.Base(path) == "package.json" {
            deps := depparser.ParseNPM(path)
            apps = append(apps, Application{Type: "npm", Deps: deps})
        }

        return nil
    })

    return apps
}
```

#### 核心依赖

- `github.com/aquasecurity/trivy` - 核心漏洞扫描
- `github.com/aquasecurity/go-dep-parser` - 依赖解析
- OSV 漏洞数据库

---

### 13. veinmind-weakpass

**位置:** `plugins/go/veinmind-weakpass/`

#### 功能说明

弱密码检测扫描器，识别默认密码和弱凭证。

#### 支持的服务

| 服务 | 版本 | 检测方式 |
|------|------|----------|
| SSH | 所有 | shadow 文件 |
| MySQL | 8.x | 数据库文件 |
| Redis | 所有 | 配置文件 |
| Tomcat | 所有 | users.xml |
| FTP | 所有 | 配置文件 |
| 容器环境变量 | - | ENV 扫描 |

#### 密码哈希格式支持

- Linux shadow (MD5, SHA-256, SHA-512)
- MySQL native password
- Windows NTLM
- 明文密码

#### 实现原理

```go
import (
    "github.com/Jeffail/tunny"
    "golang.org/x/crypto/sha512_crypt"
)

// 密码验证接口
type HashVerifier interface {
    Verify(password, hash string) bool
}

// Linux Shadow 验证器
type ShadowVerifier struct{}

func (v *ShadowVerifier) Verify(password, hash string) bool {
    // 解析哈希格式: $id$salt$hash
    parts := strings.Split(hash, "$")
    if len(parts) < 4 {
        return false
    }

    algorithm := parts[1]
    salt := parts[2]

    switch algorithm {
    case "6": // SHA-512
        computed := sha512_crypt.Crypt(password, salt)
        return computed == hash
    case "5": // SHA-256
        computed := sha256_crypt.Crypt(password, salt)
        return computed == hash
    case "1": // MD5
        computed := md5_crypt.Crypt(password, salt)
        return computed == hash
    }
    return false
}

// 并发密码测试
func bruteforce(hashes []string, passwords []string, threads int) []WeakPassword {
    pool := tunny.NewFunc(threads, func(payload interface{}) interface{} {
        args := payload.([]string)
        hash := args[0]
        password := args[1]

        if verifier.Verify(password, hash) {
            return &WeakPassword{Hash: hash, Password: password}
        }
        return nil
    })

    var results []WeakPassword
    for _, hash := range hashes {
        for _, password := range passwords {
            result := pool.Process([]string{hash, password})
            if result != nil {
                results = append(results, *result.(*WeakPassword))
            }
        }
    }

    return results
}
```

#### 密码字典

内置常见弱密码字典，支持自定义：

```
admin
password
123456
root
admin123
...
```

#### 核心依赖

- `github.com/Jeffail/tunny` - 线程池
- `golang.org/x/crypto` - 加密库
- `github.com/beevik/etree` - XML 解析

---

### 14. veinmind-webshell

**位置:** `plugins/go/veinmind-webshell/`

#### 功能说明

Webshell 检测扫描器，使用云端检测服务 (关山平台) 识别 Web 后门。

#### 支持的脚本类型

- PHP
- JSP
- ASP/ASPX
- Python
- Perl
- JavaScript

#### 实现原理

```go
import "golang.org/x/sync/errgroup"

// 脚本文件扩展名
var scriptExtensions = []string{
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".jsp", ".jspx", ".jsw", ".jsv",
    ".asp", ".aspx", ".asa", ".asax",
    ".py", ".pyw",
    ".pl", ".pm", ".cgi",
}

func scanForWebshell(image api.Image) error {
    var files []string

    // 收集脚本文件
    image.Walk("/", func(path string, info os.FileInfo, err error) error {
        if info.Mode().IsRegular() {
            ext := filepath.Ext(path)
            if isScriptFile(ext) {
                files = append(files, path)
            }
        }
        return nil
    })

    // 并发扫描
    g, ctx := errgroup.WithContext(context.Background())
    g.SetLimit(100) // 并发限制

    for _, file := range files {
        file := file
        g.Go(func() error {
            content, _ := image.ReadFile(file)
            result := detectWebshell(content)
            if result.IsWebshell {
                reportWebshell(file, result)
            }
            return nil
        })
    }

    return g.Wait()
}

// 调用关山平台 API
func detectWebshell(content []byte) *DetectionResult {
    client := &http.Client{}
    req, _ := http.NewRequest("POST", apiEndpoint, bytes.NewReader(content))
    req.Header.Set("Authorization", "Bearer "+apiToken)

    resp, _ := client.Do(req)
    var result DetectionResult
    json.NewDecoder(resp.Body).Decode(&result)

    return &result
}
```

#### 核心依赖

- `golang.org/x/sync/errgroup` - 并发错误处理
- 关山平台 API Token

---

## 插件对比表

| 插件 | 扫描目标 | 检测类型 | 云端依赖 | 规则可配置 |
|------|----------|----------|----------|------------|
| veinmind-backdoor | 镜像/容器 | 后门 | 否 | 否 |
| veinmind-basic | 镜像/容器 | 资产 | 否 | 否 |
| veinmind-escape | 镜像/容器 | 逃逸 | 否 | 是 |
| veinmind-iac | IaC 文件 | 配置 | 否 | 是 |
| veinmind-log4j2 | 镜像/容器 | 漏洞 | 否 | 否 |
| veinmind-malicious | 镜像 | 恶意软件 | 可选 | 否 |
| veinmind-minio | 镜像/容器 | 漏洞 | 否 | 否 |
| veinmind-privilege-escalation | 镜像/容器 | 提权 | 否 | 是 |
| veinmind-sensitive | 镜像 | 敏感信息 | 否 | 是 |
| veinmind-trace | 容器 | 运行时 | 否 | 否 |
| veinmind-unsafe-mount | 容器 | 配置 | 否 | 否 |
| veinmind-vuln | 镜像/容器 | 漏洞 | 否 | 否 |
| veinmind-weakpass | 镜像/容器 | 弱密码 | 否 | 是 |
| veinmind-webshell | 镜像/容器 | Webshell | 是 | 否 |

---

## 核心依赖库

### 框架依赖

| 库 | 用途 |
|----|------|
| `github.com/chaitin/libveinmind` | 容器/镜像扫描核心 API |
| `github.com/chaitin/veinmind-common-go` | 共享工具和报告服务 |
| `github.com/spf13/cobra` | CLI 命令框架 |
| `github.com/opencontainers/runtime-spec` | OCI 规范定义 |

### 功能依赖

| 库 | 用途 | 使用插件 |
|----|------|----------|
| `github.com/aquasecurity/trivy` | 漏洞扫描 | veinmind-vuln |
| `github.com/open-policy-agent/opa` | 策略引擎 | veinmind-iac |
| `github.com/testwill/go-clamd` | ClamAV 集成 | veinmind-malicious |
| `github.com/VirusTotal/vt-go` | VirusTotal API | veinmind-malicious |
| `github.com/Jeffail/tunny` | 线程池 | veinmind-weakpass |
| `golang.org/x/crypto` | 加密算法 | veinmind-weakpass |
| `github.com/BurntSushi/toml` | TOML 解析 | 多个插件 |
| `github.com/pelletier/go-toml` | TOML 解析 | veinmind-escape |
| `github.com/gabriel-vasile/mimetype` | MIME 检测 | veinmind-sensitive |
| `golang.org/x/sync` | 并发控制 | 多个插件 |
| `gorm.io/gorm` | 数据库 ORM | veinmind-malicious |
| `github.com/moby/buildkit` | Dockerfile 解析 | veinmind-iac |

---

## 参考资料

- [Veinmind Tools 官方仓库](https://github.com/chaitin/veinmind-tools)
- [Libveinmind 文档](https://github.com/chaitin/libveinmind)
- [GTFOBins](https://gtfobins.github.io/) - 提权技术参考
- [OCI 运行时规范](https://github.com/opencontainers/runtime-spec)
- [Trivy 漏洞数据库](https://github.com/aquasecurity/trivy)
