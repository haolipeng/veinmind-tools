# veinmind-backdoor 后门检测插件技术分析

**功能概述**: 检测容器和镜像中的后门程序，包括用户态后门和内核级 Rootkit。

**代码位置**: `plugins/go/veinmind-backdoor/`

---

## 1. 核心架构

采用工厂模式注册多种后门检测器：

```go
// plugins/go/veinmind-backdoor/service/base.go:11-16
type CheckFunc func(fs api.FileSystem) (bool, []*event.BackdoorDetail)

var (
    ImageCheckFuncMap     = make(map[string]CheckFunc)
    ContainerCheckFuncMap = make(map[string]CheckFunc)
)
```

**注册的检测器**:
- `rootkit` - Rootkit 检测
- `bashrc` - Bashrc 后门检测
- `ldsopreload` - LD_PRELOAD 后门检测
- `cron` - Cron 定时任务后门
- `sshd` - SSHD 软链接后门
- `inetd` - inetd 服务后门
- `xinetd` - xinetd 服务后门
- `tcpWrapper` - TCP Wrapper 后门
- `startup` - 启动脚本后门

---

## 2. Rootkit 检测原理

### 2.1 系统调用表完整性检测

```go
// plugins/go/veinmind-backdoor/service/rootkit.go:222-256
func rootkitContainerCheck(apiFileSystem api.FileSystem) (bool, []*event.BackdoorDetail) {
    // 1. 初始化内核符号表
    kallsyms := &kernel.KallSyms{}
    kcore := &kernel.KcoreMemory{}
    kmod := &kernel.KernelModules{}
    version := &kernel.KernelVersion{}

    err := initEnv(apiFileSystem, kallsyms, kcore, kmod, version)

    // 2. 获取 sys_call_table 地址
    syscallTable, ok := kallsyms.KallsymsMap["sys_call_table"]
    if !ok {
        return check, res
    }

    // 3. 读取内存中的实际系统调用地址
    memData, err := kcore.Read(syscallTable.Addr, uint64(len(kallsyms.SyscallEntry.SyscallList)*8+8))

    // 4. 对比预期地址与实际地址
    for sysNum, info := range kallsyms.SyscallEntry.SyscallList {
        addr := uint64(kernel.BytesToUint(memData[sysNum*8 : sysNum*8+8]))

        // 地址有效性检查
        if addr < uint64(0xffff800000000000) || addr > uint64(0xffffffffffff8000) {
            continue
        }

        if addr != info.Addr {
            // 检查是否在内核代码段范围内
            if kcore.TextAddr <= addr && addr < kcore.KernelTextRange {
                continue
            }

            // 系统调用被劫持！查找劫持模块
            module, err := findModule(addr, kcore, kmod, version)
            if err != nil {
                continue
            }

            if module.Name != "" {
                check = true
                res = append(res, &event.BackdoorDetail{
                    FileDetail:  kmod.ModDetail,
                    Content:     module.Name + ": " + strconv.FormatUint(module.Addr, 16),
                    Description: kernel.DefaultDescription,
                })
            }
        }
    }

    return check, res
}
```

**检测原理**:
1. 解析 `/proc/kallsyms` 获取内核符号地址
2. 通过 `/dev/kcore` 读取内核内存
3. 比对 `sys_call_table` 中的系统调用地址与预期地址
4. 不匹配则表示系统调用被劫持

### 2.2 模块查找算法

```go
// plugins/go/veinmind-backdoor/service/rootkit.go:30-56
func findModule(
    addr uint64,
    kcore *kernel.KcoreMemory,
    kmod *kernel.KernelModules,
    version *kernel.KernelVersion,
) (kernel.ModuleInfo, error) {
    // 二分查找已知模块
    pos := kmod.BinarySearch(addr)
    if pos < 0 {
        return kernel.ModuleInfo{}, kernel.ErrInvalidNum
    } else if pos != 0 {
        prevModule := *kmod.ModuleList[pos-1]
        moduleRange := prevModule.Addr + prevModule.Size
        if addr < moduleRange {
            return prevModule, nil
        } else if pos != len(kmod.ModuleList) && addr == kmod.ModuleList[pos].Addr {
            return *kmod.ModuleList[pos], nil
        }
    }

    // 从内核内存中查找模块信息
    modInfo, err := kcore.FindModule(addr, kmod.ModOffset, version)
    if err != nil {
        return kernel.ModuleInfo{}, err
    }

    // 插入到有序列表中
    kmod.Insert(pos, &modInfo)

    return modInfo, nil
}
```

---

## 3. /proc/kallsyms 解析

```go
// plugins/go/veinmind-backdoor/kernel/kallsyms.go:57-109
func (kallsyms *KallSyms) Init(apiFileSystem api.FileSystem) error {
    sort.Strings(SymsBuiltinList)
    syscallEntry := &Ksyscall{}
    syscallEntry.Init()
    kallsymsMap := make(map[string]KallsymsEntry)

    file, err := apiFileSystem.Open(KallsymsPath)
    if err != nil {
        return err
    }
    defer file.Close()

    zeroAddressCount := 0
    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Fields(line)

        addr, err := strconv.ParseUint(fields[0], 16, 64)
        if err != nil {
            return err
        }

        // 检测全零地址（无权限读取 kallsyms）
        if addr == 0 {
            zeroAddressCount++
            if zeroAddressCount > MaxZeroAddresses {
                return ErrKallsymsAddr
            }
        }

        // 更新系统调用表
        isUpdated := false
        if fields[1] < "a" {  // 大写类型表示全局符号
            isUpdated = syscallEntry.UpdateSyscall(fields[2], fields[1], addr)
        }

        // 缓存关键符号
        if !isUpdated && sort.SearchStrings(SymsBuiltinList, fields[2]) < len(SymsBuiltinList) {
            kallsymsMap[fields[2]] = KallsymsEntry{Addr: addr, Type: fields[1]}
        }
    }

    kallsyms.SyscallEntry = syscallEntry
    kallsyms.KallsymsMap = kallsymsMap

    return nil
}
```

### 3.1 符号类型说明

| 类型 | 含义 |
|------|------|
| T | 代码段全局符号 |
| t | 代码段局部符号 |
| D | 数据段全局符号 |
| d | 数据段局部符号 |
| W | 弱符号 |

---

## 4. 用户态后门检测

### 4.1 Bashrc 后门检测

```go
// plugins/go/veinmind-backdoor/service/bashrc.go:11-106
func bashrcBackdoorCheck(apiFileSystem api.FileSystem) (bool, []*event.BackdoorDetail) {
    filePaths := []string{
        "/root/.bashrc",
        "/root/.tcshrc",
        "/root/.bash_profile",
        "/root/.cshrc",
        "/etc/.bashrc",
        "/etc/bashrc",
        "/etc/profile",
    }
    profileDir := "/etc/profile.d"
    homeDir := "/home"
    homeFiles := []string{".bashrc", ".bash_profile", ".tcshrc", ".cshrc"}

    check := false
    var res []*event.BackdoorDetail

    // 检查 /root 和 /etc 下的 shell 配置文件
    for _, filepath := range filePaths {
        fileInfo, err := apiFileSystem.Stat(filepath)
        if err != nil {
            continue
        }

        file, err := apiFileSystem.Open(filepath)
        if err != nil {
            continue
        }
        defer file.Close()

        contents, _ := io.ReadAll(file)

        // 分析恶意字符串模式
        risk, content := analysisStrings(string(contents))
        if risk {
            check = true
            fileDetail, _ := file2FileDetail(fileInfo, filepath)
            res = append(res, &event.BackdoorDetail{
                FileDetail:  fileDetail,
                Content:     content,
                Description: "env backdoor",
            })
        }
    }

    // 检查 /etc/profile.d 目录
    apiFileSystem.Walk(profileDir, func(path string, info fs.FileInfo, err error) error {
        file, _ := apiFileSystem.Open(path)
        contents, _ := io.ReadAll(file)
        risk, content := analysisStrings(string(contents))
        if risk {
            // 报告后门
        }
        return nil
    })

    // 检查 /home 下用户的 shell 配置文件
    apiFileSystem.Walk(homeDir, func(path string, info fs.FileInfo, err error) error {
        for _, filename := range homeFiles {
            if info.Name() == filename {
                // 检查并报告
            }
        }
        return nil
    })

    return check, res
}

func init() {
    ImageCheckFuncMap["bashrc"] = bashrcBackdoorCheck
    ContainerCheckFuncMap["bashrc"] = bashrcBackdoorCheck
}
```

### 4.2 已知 Rootkit 规则检测

```go
// plugins/go/veinmind-backdoor/service/rootkit.go:78-98
func rootkitRuleCheck(apiFileSystem api.FileSystem) (bool, []*event.BackdoorDetail) {
    var res []*event.BackdoorDetail
    check := false

    for _, rootkitInfo := range kernel.RootkitRules {
        checkPaths := append(rootkitInfo.File, rootkitInfo.Dir...)

        for _, path := range checkPaths {
            if checkRes := rootkitPathCheck(apiFileSystem, rootkitInfo.Name, path); checkRes != nil {
                check = true
                res = append(res, checkRes)
            }
        }
    }

    return check, res
}
```

### 4.3 恶意 LKM 检测

```go
// plugins/go/veinmind-backdoor/service/rootkit.go:100-131
func rootkitLKMCheck(apiFileSystem api.FileSystem) (bool, []*event.BackdoorDetail) {
    check := false
    var res []*event.BackdoorDetail

    dirLKM, err := apiFileSystem.Lstat(kernel.LKMDir)
    if err != nil || !dirLKM.IsDir() {
        return false, nil
    }

    apiFileSystem.Walk(kernel.LKMDir, func(path string, info fs.FileInfo, err error) error {
        ext := strings.ToLower(filepath.Ext(path))

        // 检查 .so, .ko, .ko.xz 文件
        if ext == ".so" || ext == ".ko" || ext == ".ko.xz" {
            for _, lkm := range kernel.BadLKM {
                if lkm == strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ext) {
                    check = true
                    res = append(res, &event.BackdoorDetail{
                        Content:     path,
                        Description: kernel.DefaultDescription,
                    })
                }
            }
        }
        return err
    })

    return check, res
}
```

---

## 5. 支持的后门类型

| 类型 | 检测位置 | 说明 |
|------|---------|------|
| bashrc | `~/.bashrc`, `/etc/profile` 等 | 环境变量/别名后门 |
| LD_PRELOAD | `/etc/ld.so.preload` | 动态库预加载后门 |
| Cron | `/etc/crontab`, `/var/spool/cron/` | 定时任务后门 |
| SSHD | `/usr/sbin/sshd` | 软链接后门 |
| inetd | `/etc/inetd.conf` | 超级服务后门 |
| xinetd | `/etc/xinetd.d/` | 扩展超级服务后门 |
| TCP Wrapper | `/etc/hosts.allow` | 访问控制后门 |
| Startup | `/etc/init.d/`, systemd 服务 | 启动脚本后门 |
| Rootkit | 内核模块 | 系统调用劫持 |

---

## 6. 检测流程

```
┌─────────────────────────────────────────────────┐
│                 后门检测流程                      │
├─────────────────────────────────────────────────┤
│  1. 用户态后门检测                               │
│     ├─ bashrc 后门                              │
│     ├─ LD_PRELOAD 后门                          │
│     ├─ Cron 后门                                │
│     ├─ SSHD 后门                                │
│     └─ 其他服务后门                              │
├─────────────────────────────────────────────────┤
│  2. 内核态检测 (仅容器)                          │
│     ├─ 已知 Rootkit 规则匹配                    │
│     ├─ 恶意 LKM 检测                            │
│     └─ 系统调用表完整性验证                      │
└─────────────────────────────────────────────────┘
```

---

*文档生成时间: 2026-01-20*
