# veinmind-escape 容器逃逸风险检测插件技术分析

**功能概述**: 检测容器配置中可能导致逃逸的安全风险。

**代码位置**: `plugins/go/veinmind-escape/`

---

## 1. 核心架构

```go
// plugins/go/veinmind-escape/pkg/report.go
var (
    ContainerCheckList = make([]CheckFunc, 0)
    ImageCheckList     = make([]CheckFunc, 0)
)

type CheckFunc func(fs api.FileSystem) ([]*event.EscapeDetail, error)
```

**注册的检测器**:
- `ContainerCVECheck` - CVE 漏洞检测
- `ContainerUnsafeCapCheck` - 危险能力检测
- `ContainerUnsafeMount` - 不安全挂载检测
- `UnsafePrivCheck` - 权限检测
- `UnsafeSuidCheck` - SUID 检测
- `CheckEmptyPasswdRoot` - 空密码 root 检测

---

## 2. CVE 版本范围匹配算法

### 2.1 规则解析

```go
// plugins/go/veinmind-escape/pkg/cve.go:139-235
func parserVersion(version string) versionCheck {
    // 解析版本范围表达式，如: "1.1.1<ver<=2.2.2"
    res := strings.Split(version, "ver")
    versionCheck1 := versionCheck{}

    if res[0] != "" && res[1] != "" {
        // 双边界格式: 1.1.1<ver<=2.2.2
        var opera1, opera2 string

        // 解析左边界
        for i := 0; i < len(res[0]); i++ {
            if string(res[0][i]) == "=" || string(res[0][i]) == "<" || string(res[0][i]) == ">" {
                opera1 = res[0][i:]
                res[0] = res[0][:i]
                break
            }
        }

        // 解析右边界
        for i := 0; i < len(res[1]); i++ {
            if unicode.IsNumber(rune(res[1][i])) {
                opera2 = res[1][:i]
                res[1] = res[1][i:]
                break
            }
        }

        // 根据操作符设置边界
        switch opera1 {
        case "<=":
            versionCheck1.BeginVersion = res[0]
            versionCheck1.BeginEqual = true
        case "<":
            versionCheck1.BeginVersion = res[0]
            versionCheck1.BeginEqual = false
        case ">":
            versionCheck1.EndVersion = res[0]
            versionCheck1.EndEqual = false
        case ">=":
            versionCheck1.EndVersion = res[0]
            versionCheck1.EndEqual = true
        }
        // ... 处理右边界
    } else {
        // 单边界格式: ver>=3.3.3
        // ...
    }

    return versionCheck1
}
```

### 2.2 版本比较

```go
// plugins/go/veinmind-escape/pkg/cve.go:255-297
func morethan(cveVersion []int, inputVersion []int, equal bool) bool {
    if cveVersion[0] == -1 && cveVersion[1] == -1 && cveVersion[2] == -1 {
        return true  // 无限制
    }

    if equal && cveVersion[0] == inputVersion[0] &&
       cveVersion[1] == inputVersion[1] &&
       cveVersion[2] == inputVersion[2] {
        return true
    }

    // 逐级比较
    if inputVersion[0] > cveVersion[0] {
        return true
    } else if inputVersion[0] == cveVersion[0] {
        if inputVersion[1] > cveVersion[1] {
            return true
        } else if inputVersion[1] == cveVersion[1] {
            if inputVersion[2] > cveVersion[2] {
                return true
            }
        }
    }
    return false
}

func lessthan(cveVersion []int, inputVersion []int, equal bool) bool {
    // 类似 morethan，方向相反
}
```

### 2.3 规则配置 (TOML)

```toml
# rules/rule.toml
[[cve]]
cveNumber = "CVE-2022-0185"
version = ["5.1<=ver<5.16.2"]

[[cve]]
cveNumber = "CVE-2022-0492"
version = ["ver<5.17"]

[[cve]]
cveNumber = "CVE-2021-22555"
version = ["2.6.19<=ver<5.13"]
```

---

## 3. Linux Capabilities 危险能力检测

### 3.1 危险能力列表

```go
// plugins/go/veinmind-escape/pkg/priv.go:21
var UnSafeCapList = []string{
    "CAP_DAC_READ_SEARCH",  // 绕过文件读权限检查
    "CAP_SYS_MODULE",       // 加载/卸载内核模块
    "CAP_SYS_PTRACE",       // 进程跟踪
    "CAP_SYS_ADMIN",        // 系统管理（最危险）
    "CAP_DAC_OVERRIDE",     // 绕过文件权限检查
}
```

### 3.2 能力检测实现

```go
// plugins/go/veinmind-escape/pkg/priv.go:78-119
func ContainerUnsafeCapCheck(fs api.FileSystem) ([]*event.EscapeDetail, error) {
    var res = make([]*event.EscapeDetail, 0)

    container, ok := fs.(api.Container)
    if !ok {
        return nil, nil
    }

    // 获取容器能力
    err := getCapEff(container)
    if err != nil {
        return nil, err
    }

    // 检查是否为特权容器
    if isPrivileged(container) {
        res = append(res, &event.EscapeDetail{
            Target: "LINUX CAPABILITY",
            Reason: CAPREASON,
            Detail: "UnSafeCapability PRIVILEGED",
        })
    } else {
        // 检查危险能力交集
        UnSafeCap := intersect(cap, UnSafeCapList)

        for _, value := range UnSafeCap {
            if value == "CAP_SYS_PTRACE" {
                // CAP_SYS_PTRACE 需要配合 pid=host 才危险
                if isPidEqualHost(container) {
                    res = append(res, &event.EscapeDetail{
                        Target: "LINUX CAPABILITY",
                        Reason: CAPREASON,
                        Detail: "UnSafeCapability " + value + " and pid=host",
                    })
                }
            } else {
                res = append(res, &event.EscapeDetail{
                    Target: "LINUX CAPABILITY",
                    Reason: CAPREASON,
                    Detail: "UnSafeCapability " + value,
                })
            }
        }
    }

    return res, nil
}
```

### 3.3 特权容器检测

```go
// plugins/go/veinmind-escape/pkg/priv.go:163-198
func isPrivileged(container api.Container) bool {
    state, err := container.OCIState()
    if err != nil || state.Pid == 0 {
        return false
    }

    // 读取进程状态
    status, err := os.ReadFile(filepath.Join(
        func() string {
            fs := os.Getenv("LIBVEINMIND_HOST_ROOTFS")
            if fs == "" { return "/" }
            return fs
        }(),
        "proc",
        strconv.Itoa(state.Pid),
        "status",
    ))
    if err != nil {
        return false
    }

    // 匹配 CapEff 字段
    pattern := regexp.MustCompile(`(?i)capeff:\s*?([a-z0-9]+)\s`)
    matched := pattern.FindStringSubmatch(string(status))

    if len(matched) != 2 {
        return false
    }

    // 全 f 表示特权模式 (0xffffffff)
    return strings.HasSuffix(matched[1], "ffffffff")
}
```

### 3.4 pid 命名空间检测

```go
// plugins/go/veinmind-escape/pkg/priv.go:200-212
func isPidEqualHost(container api.Container) bool {
    spec, err := container.OCISpec()
    if err != nil {
        return false
    }

    namespaces := spec.Linux.Namespaces
    for _, value := range namespaces {
        if value.Type == "pid" {
            return false  // 存在 pid 命名空间，非 host 模式
        }
    }
    return true  // 无 pid 命名空间，共享宿主机
}
```

---

## 4. 不安全挂载检测

### 4.1 危险路径列表

```go
// plugins/go/veinmind-escape/pkg/mount.go:10-31
var UnsafeMountPaths = []string{
    "/lxcfs",
    "/",
    "/etc",
    "/var",
    "/proc",
    "/sys",
    "/etc/crontab",
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh",

    // 容器运行时 Socket
    "/var/run/docker.sock",
    "/run/containerd.sock",
    "/var/run/crio/crio.sock",

    // Kubernetes 相关
    "/var/lib/kubelet",
    "/var/lib/kubelet/pki",
    "/etc/kubernetes",
    "/etc/kubernetes/manifests",
    "/var/log",
}
```

### 4.2 挂载检测实现

```go
// plugins/go/veinmind-escape/pkg/mount.go:33-65
func ContainerUnsafeMount(fs api.FileSystem) ([]*event.EscapeDetail, error) {
    var res = make([]*event.EscapeDetail, 0)

    container := fs.(api.Container)
    spec, err := container.OCISpec()
    if err != nil {
        return res, err
    }

    for _, mount := range spec.Mounts {
        for _, pattern := range UnsafeMountPaths {
            matched, _ := filepath.Match(pattern, mount.Source)
            if matched {
                // /var/log 逃逸仅在 K8s 环境下有效
                if pattern == "/var/log" {
                    // 检查是否存在 K8s ServiceAccount Token
                    if _, err := fs.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err != nil {
                        continue  // 非 K8s 容器，跳过
                    }
                }

                res = append(res, &event.EscapeDetail{
                    Target: mount.Source,
                    Reason: MOUNTREASON,
                    Detail: "UnSafeMountDestination " + mount.Destination,
                })
            }
        }
    }
    return res, nil
}
```

---

## 5. 权限与 SUID 检测

### 5.1 文件权限检测

```go
// plugins/go/veinmind-escape/pkg/priv.go:23-52
func UnsafePrivCheck(fs api.FileSystem) ([]*event.EscapeDetail, error) {
    var res = make([]*event.EscapeDetail, 0)

    taskMap := make(map[checkMode][]string)
    taskMap[WRITE] = []string{"/etc/passwd", "/etc/crontab"}
    taskMap[READ] = []string{"/etc/shadow"}

    for _, task := range taskMap[WRITE] {
        if priv, ok, _ := privCheck(fs, task, WRITE); ok {
            res = append(res, &event.EscapeDetail{
                Target: task,
                Reason: WRITEREASON,
                Detail: "UnSafePriv " + priv,
            })
        }
    }

    for _, task := range taskMap[READ] {
        if priv, ok, _ := privCheck(fs, task, READ); ok {
            res = append(res, &event.EscapeDetail{
                Target: task,
                Reason: READREASON,
                Detail: "UnSafePriv " + priv,
            })
        }
    }
    return res, nil
}
```

### 5.2 SUID 二进制检测

```go
// plugins/go/veinmind-escape/pkg/priv.go:54-76
func UnsafeSuidCheck(fs api.FileSystem) ([]*event.EscapeDetail, error) {
    var res = make([]*event.EscapeDetail, 0)

    var binaryName = []string{"bash", "nmap", "vim", "find", "more", "less", "nano", "cp", "awk"}
    var filepath = []string{"/bin/", "/usr/bin/"}

    for i := 0; i < len(filepath); i++ {
        for j := 0; j < len(binaryName); j++ {
            files := filepath[i] + binaryName[j]
            content, err := fs.Stat(files)
            if err == nil {
                if isBelongToRoot(content) && isContainSUID(content) {
                    res = append(res, &event.EscapeDetail{
                        Target: files,
                        Reason: SUIDREASON,
                        Detail: "UnSafePriv " + content.Mode().String(),
                    })
                }
            }
        }
    }
    return res, nil
}
```

---

## 6. 检测风险分类

| 风险类型 | 检测项 | 严重程度 |
|---------|--------|---------|
| CVE 漏洞 | 内核版本匹配 | Critical |
| 特权容器 | CapEff = ffffffff | Critical |
| 危险能力 | CAP_SYS_ADMIN 等 | High |
| Docker Socket | /var/run/docker.sock | Critical |
| 敏感目录挂载 | /, /etc, /proc 等 | High |
| SUID 二进制 | bash, vim 等 | Medium |
| 弱权限文件 | /etc/passwd 可写 | High |

---

*文档生成时间: 2026-01-20*
