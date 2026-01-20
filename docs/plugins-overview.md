# Veinmind Go 插件技术分析 - 概述

本系列文档基于源代码深度分析，详细讲解 Veinmind 插件的核心实现原理、关键算法和设计模式。

## 文档索引

| 分类 | 文档 | 说明 |
|------|------|------|
| 架构概述 | [plugins-overview.md](./plugins-overview.md) | 本文档 |
| 漏洞扫描 | [plugins-vulnerability-scanning.md](./plugins-vulnerability-scanning.md) | vuln, log4j2, minio |
| 敏感信息 | [plugins-sensitive-info.md](./plugins-sensitive-info.md) | sensitive, weakpass |
| 配置审计 | [plugins-config-audit.md](./plugins-config-audit.md) | iac, unsafe-mount |
| 信息收集 | [plugins-info-collection.md](./plugins-info-collection.md) | basic |

### 安全检测类插件 (独立文档)

| 插件 | 文档 | 功能 |
|------|------|------|
| veinmind-backdoor | [plugin-backdoor.md](./plugin-backdoor.md) | 后门检测 (Rootkit、bashrc、LD_PRELOAD 等) |
| veinmind-escape | [plugin-escape.md](./plugin-escape.md) | 容器逃逸风险检测 (CVE、Capabilities、危险挂载) |
| veinmind-trace | [plugin-trace.md](./plugin-trace.md) | 运行时威胁检测 (隐藏进程、反弹 Shell) |
| veinmind-privilege-escalation | [plugin-privilege-escalation.md](./plugin-privilege-escalation.md) | 提权风险检测 (GTFOBins、SUID、Sudo) |
| veinmind-malicious | [plugin-malicious.md](./plugin-malicious.md) | 恶意文件扫描 (ClamAV + VirusTotal 双引擎) |
| veinmind-webshell | [plugin-webshell.md](./plugin-webshell.md) | Webshell 检测 (云端检测服务) |

---

## 一、插件框架设计

Veinmind 插件基于 `libveinmind` 库构建，采用统一的命令行接口模式：

```go
// 核心接口定义 (libveinmind/go)
type FileSystem interface {
    Open(path string) (File, error)
    Stat(path string) (os.FileInfo, error)
    Walk(root string, walkFn filepath.WalkFunc) error
    Lstat(path string) (os.FileInfo, error)
}

type Image interface {
    FileSystem
    ID() string
    RepoRefs() ([]string, error)
    OCISpecV1() (*v1.Image, error)
}

type Container interface {
    FileSystem
    ID() string
    Name() string
    OCISpec() (*specs.Spec, error)
    OCIState() (*specs.State, error)
    Pids() ([]int32, error)
}
```

**设计亮点：**
- 通过 `api.FileSystem` 接口抽象文件系统访问，支持镜像和容器的统一扫描
- 使用 OCI 规范接口获取容器/镜像元数据
- 支持 Docker 和 Containerd 多运行时适配

---

## 二、统一的命令结构

所有插件采用相同的命令模式：

```go
// 标准插件结构
var rootCmd = &cmd.Command{}
var scanCmd = &cmd.Command{Use: "scan"}
var scanImageCmd = &cmd.Command{Use: "image"}
var scanContainerCmd = &cmd.Command{Use: "container"}

func init() {
    rootCmd.AddCommand(scanCmd)
    scanCmd.AddCommand(report.MapReportCmd(
        cmd.MapImageCommand(scanImageCmd, scanImage),
        reportService,
    ))
    scanCmd.AddCommand(report.MapReportCmd(
        cmd.MapContainerCommand(scanContainerCmd, scanContainer),
        reportService,
    ))
}
```

---

## 三、统一的报告机制

```go
type Event struct {
    BasicInfo  *BasicInfo  // 基础信息：ID、时间、级别、来源
    DetailInfo *DetailInfo // 详细信息：告警详情
}

type BasicInfo struct {
    ID         string
    Time       time.Time
    Level      Level       // None/Low/Medium/High/Critical
    Source     string
    EventType  EventType   // Risk/Invasion/Info
    DetectType DetectType  // Image/Container
    AlertType  AlertType   // 具体告警类型
}
```

---

## 四、并发控制模式

| 模式 | 插件 | 适用场景 |
|------|------|---------|
| `semaphore.Weighted` | veinmind-vuln | IO 密集型任务，加权信号量 |
| `errgroup.SetLimit` | veinmind-sensitive, veinmind-webshell | 批量文件扫描，自动错误传播 |
| `tunny.Pool` | veinmind-weakpass | CPU 密集型任务，固定线程池 |

```go
// semaphore.Weighted
limit := semaphore.NewWeighted(parallel)
limit.Acquire(ctx, 1)
defer limit.Release(1)

// errgroup.SetLimit
eg := errgroup.Group{}
eg.SetLimit(100)
eg.Go(func() error { ... })
eg.Wait()

// tunny.Pool
pool := tunny.NewFunc(threads, func(payload interface{}) interface{} {
    return process(payload)
})
result := pool.Process(payload)
```

---

## 五、缓存优化策略

```
┌─────────────────────────────────────────────────┐
│                 三级缓存架构                      │
├─────────────────────────────────────────────────┤
│  Level 1: 白名单缓存 (WhitePath)                 │
│  └─ 快速跳过已知安全路径                          │
├─────────────────────────────────────────────────┤
│  Level 2: 路径规则缓存 (PathRule)                │
│  └─ 相同路径复用规则匹配结果                      │
├─────────────────────────────────────────────────┤
│  Level 3: 哈希规则缓存 (HashRule)                │
│  └─ 相同文件内容只扫描一次                        │
└─────────────────────────────────────────────────┘
```

**正则编译缓存** (sync.Map):
```go
var regexMap = sync.Map{}

func getRegexp(pattern string) (*regexp.Regexp, error) {
    if loaded, ok := regexMap.Load(pattern); ok {
        return loaded.(*regexp.Regexp), nil
    }
    regex, _ := regexp.Compile(pattern)
    regexMap.Store(pattern, regex)
    return regex, nil
}
```

---

## 六、规则引擎设计

| 格式 | 插件 | 优势 |
|------|------|-----|
| TOML | veinmind-escape, veinmind-privilege-escalation | 简洁易读，适合版本范围 |
| Rego | veinmind-iac | 强大的策略语言，支持复杂逻辑 |
| 正则 | veinmind-sensitive | 灵活匹配，适合敏感信息检测 |

---

## 七、设计模式总结

| 模式 | 应用场景 | 插件示例 | 代码位置 |
|------|---------|---------|---------|
| **策略模式** | Hash 接口多实现 | veinmind-weakpass | `hash/base.go` |
| **工厂模式** | 服务/检测器注册 | veinmind-weakpass, veinmind-backdoor | `service/register.go` |
| **适配器模式** | 多运行时支持 | veinmind-basic | `cmd/basic/cli.go` |
| **观察者模式** | 分析器组合 | veinmind-trace | `pkg/analyzer/analyzer.go` |
| **模板方法** | 扫描流程 | 所有插件 | `cmd/*.go` |
| **单例模式** | 配置管理 | veinmind-sensitive | `rule/rule.go` |
| **建造者模式** | Kit 构造 | veinmind-webshell | `pkg/detect/detect.go` |

---

## 八、技术分享建议

### 推荐主题

1. **容器安全检测的多层架构** - 从静态扫描到运行时检测
2. **内核级 Rootkit 检测原理** - /proc/kallsyms 与 sys_call_table
3. **OPA 策略引擎在 IaC 扫描中的应用** - Rego 规则编写
4. **高效敏感信息扫描的缓存策略** - 三级缓存设计

### 源码快速索引

| 插件 | 主入口 | 核心逻辑 |
|------|--------|---------|
| veinmind-backdoor | `cmd/cli.go` | `service/rootkit.go`, `kernel/kallsyms.go` |
| veinmind-escape | `cmd/cli.go` | `pkg/cve.go`, `pkg/priv.go`, `pkg/mount.go` |
| veinmind-trace | `cmd/cli.go` | `pkg/security/process.go`, `pkg/analyzer/` |
| veinmind-privilege-escalation | `cmd/cli.go` | `rules/parse.go`, `service/suid.go` |
| veinmind-malicious | `cmd/scan/cli.go` | `scanner/malicious/scan.go`, `sdk/av/` |
| veinmind-webshell | `cmd/webshell/cmd.go` | `pkg/detect/detect.go` |
| veinmind-vuln | `cmd/cli.go` | `analyzer/analyzer.go`, `analyzer/osv.go` |
| veinmind-log4j2 | `cmd/cli.go` | `pkg/scanner/scanner.go` |
| veinmind-minio | `cmd/cli.go` | `pkg/scanner/scanner.go` |
| veinmind-sensitive | `cmd/cli.go` | `cmd/scan.go`, `cache/`, `vregex/` |
| veinmind-weakpass | `cmd/cli.go` | `hash/`, `service/`, `utils/utils.go` |
| veinmind-iac | `cmd/cli.go` | `pkg/scanner/scanner.go`, `pkg/parser/` |
| veinmind-unsafe-mount | `cmd/cli.go` | `pkg/engine/detect.go` |
| veinmind-basic | `cmd/basic/cli.go` | `pkg/capability/cap.go` |

---

*文档生成时间: 2026-01-20*
