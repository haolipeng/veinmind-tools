# veinmind-privilege-escalation 提权风险检测插件技术分析

**功能概述**: 检测可能用于权限提升的可执行文件和配置。

**代码位置**: `plugins/go/veinmind-privilege-escalation/`

---

## 1. 核心架构

采用工厂模式注册多种检测器：

```go
// plugins/go/veinmind-privilege-escalation/service/base.go:9-18
type CheckFunc func(fs api.FileSystem, content os.FileInfo, filename string) (bool, error)

var (
    ImageCheckFuncMap     = make(map[string]CheckFunc)
    ContainerCheckFuncMap = make(map[string]CheckFunc)
)

const (
    SUDOREGEX string = `(\w{1,})\s\w{1,}=\(.*\)\s(.*)`
)
```

**注册的检测器**:
- `suid` - SUID 二进制检测
- `sudo` - Sudo 配置检测
- `cap` - Capabilities 检测

---

## 2. GTFOBins 规则库集成

### 2.1 规则结构定义

```go
// plugins/go/veinmind-privilege-escalation/rules/parse.go:8-38
type Exp struct {
    Exp string `toml:"exp"`  // 利用 Payload
}

type Exps struct {
    Shell                      []*Exp `toml:"shell"`
    Command                    []*Exp `toml:"command"`
    ReverseShell               []*Exp `toml:"reverse-shell"`
    NonInteractiveReverseShell []*Exp `toml:"non-interactive-reverse-shell"`
    BindShell                  []*Exp `toml:"bind-shell"`
    NonInteractiveBindShell    []*Exp `toml:"non-interactive-bind-shell"`
    FileUpload                 []*Exp `toml:"file-upload"`
    FileDownload               []*Exp `toml:"file-download"`
    FileWrite                  []*Exp `toml:"file-write"`
    FileRead                   []*Exp `toml:"file-read"`
    LibraryLoad                []*Exp `toml:"library-load"`
    SUID                       []*Exp `toml:"suid"`
    Sudo                       []*Exp `toml:"sudo"`
    Capabilities               []*Exp `toml:"capabilities"`
    LimitedSUID                []*Exp `toml:"limited-suid"`
}

type Rule struct {
    Name        string   `toml:"Name"`
    Description string   `toml:"Description"`
    Tags        []string `toml:"Tags"`
    Exps        Exps     `toml:"exps"`
}

type Config struct {
    Rules []*Rule `toml:"privilege-esclation"`
}
```

### 2.2 规则加载

```go
// plugins/go/veinmind-privilege-escalation/rules/parse.go:40-53
func GetRuleFromFile() (*Config, error) {
    var config Config

    content, err := Readfile("rule.toml")
    if err != nil {
        log.Fatal(err)
    }

    if err := toml.Unmarshal(content, &config); err != nil {
        log.Error(err)
        return nil, err
    }

    return &config, nil
}
```

### 2.3 规则示例 (TOML)

```toml
# rules/rule.toml
[[privilege-esclation]]
Name = "vim"
Description = "Vim text editor"
Tags = ["editor", "file-read", "file-write"]

[privilege-esclation.exps]
shell = [
    { exp = 'vim -c ":!/bin/sh"' },
    { exp = 'vim -c ":set shell=/bin/sh" -c ":shell"' }
]
suid = [
    { exp = './vim -c ":py import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")"' },
    { exp = './vim -c ":lua os.execute(\"/bin/sh -p\")"' }
]
sudo = [
    { exp = 'sudo vim -c ":!/bin/sh"' }
]

[[privilege-esclation]]
Name = "find"
Description = "GNU find utility"
Tags = ["file-search", "command-execution"]

[privilege-esclation.exps]
shell = [
    { exp = 'find . -exec /bin/sh \\; -quit' }
]
suid = [
    { exp = './find . -exec /bin/sh -p \\; -quit' }
]

[[privilege-esclation]]
Name = "python"
Description = "Python interpreter"
Tags = ["interpreter", "shell"]

[privilege-esclation.exps]
shell = [
    { exp = 'python -c "import os; os.system(\"/bin/sh\")"' }
]
suid = [
    { exp = './python -c "import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")"' }
]
capabilities = [
    { exp = './python -c "import os; os.setuid(0); os.system(\"/bin/sh\")"' }
]
```

---

## 3. SUID 二进制检测

### 3.1 检测实现

```go
// plugins/go/veinmind-privilege-escalation/service/suid.go:12-35
func SuidCheck(fs api.FileSystem, content os.FileInfo, filename string) (bool, error) {
    return isBelongToRoot(content) && isContainSUID(content), nil
}

func isBelongToRoot(content os.FileInfo) bool {
    uid := content.Sys().(*syscall.Stat_t).Uid
    return uid == uint32(0)
}

func isContainSUID(content os.FileInfo) bool {
    res := fmt.Sprintf("%o", uint32(content.Mode()))
    // 4000 = SUID
    // 6000 = SUID + SGID
    return strings.HasPrefix(res, "4000") || strings.HasPrefix(res, "6000")
}

func init() {
    ImageCheckFuncMap["suid"] = SuidCheck
    ContainerCheckFuncMap["suid"] = SuidCheck
}
```

### 3.2 SUID 原理说明

| 权限位 | 八进制 | 含义 |
|--------|--------|------|
| SUID | 4000 | 以文件所有者权限执行 |
| SGID | 2000 | 以文件所属组权限执行 |
| Sticky | 1000 | 仅所有者可删除 |

**危险条件**:
- 文件所有者为 root (UID=0)
- 设置了 SUID 位 (4000 或 6000)
- 文件在 GTFOBins 规则库中

---

## 4. Sudo 配置检测

```go
// plugins/go/veinmind-privilege-escalation/service/sudo.go
func SudoCheck(fs api.FileSystem, content os.FileInfo, filename string) (bool, error) {
    // 解析 /etc/sudoers 和 /etc/sudoers.d/
    // 匹配模式: user host=(runas) command
    pattern := regexp.MustCompile(SUDOREGEX)
    // ...
}
```

**Sudoers 规则格式**:
```
# 用户 主机=(运行身份) 命令
alice ALL=(ALL) /usr/bin/vim
bob   ALL=(root) NOPASSWD: /usr/bin/find
```

---

## 5. Capabilities 检测

```go
// plugins/go/veinmind-privilege-escalation/service/cap.go
func CapCheck(fs api.FileSystem, content os.FileInfo, filename string) (bool, error) {
    // 检查文件是否具有危险 Capabilities
    // 常见危险能力:
    // - cap_setuid: 可以切换 UID
    // - cap_net_raw: 原始套接字
    // - cap_dac_read_search: 绕过读权限
}
```

**危险 Capabilities**:

| 能力 | 风险 |
|------|------|
| cap_setuid | 可以提权到任意用户 |
| cap_setgid | 可以切换到任意组 |
| cap_chown | 可以更改文件所有者 |
| cap_dac_override | 绕过权限检查 |
| cap_sys_admin | 几乎等同于 root |

---

## 6. 检测流程

```
┌─────────────────────────────────────────────────┐
│               提权风险检测流程                    │
├─────────────────────────────────────────────────┤
│  1. 加载 GTFOBins 规则库                         │
│     └─ 解析 rule.toml 配置文件                   │
├─────────────────────────────────────────────────┤
│  2. 遍历文件系统                                 │
│     ├─ /bin, /usr/bin, /sbin, /usr/sbin        │
│     └─ /usr/local/bin 等                        │
├─────────────────────────────────────────────────┤
│  3. 对每个可执行文件执行检测                      │
│     ├─ SUID 检测                                │
│     │   ├─ 文件所有者是否为 root                 │
│     │   └─ 是否设置 SUID 位                      │
│     ├─ Capabilities 检测                        │
│     │   └─ 是否具有危险能力                      │
│     └─ 规则匹配                                  │
│         └─ 文件名是否在 GTFOBins 中              │
├─────────────────────────────────────────────────┤
│  4. 检查 Sudo 配置                               │
│     ├─ /etc/sudoers                             │
│     └─ /etc/sudoers.d/*                         │
└─────────────────────────────────────────────────┘
```

---

## 7. 利用类型说明

| 类型 | 说明 | 示例 |
|------|------|------|
| shell | 获取交互式 Shell | `vim -c ':!/bin/sh'` |
| command | 执行任意命令 | `find . -exec cmd \;` |
| reverse-shell | 反弹 Shell | 连接到攻击者 |
| file-read | 读取任意文件 | 读取 /etc/shadow |
| file-write | 写入任意文件 | 写入 /etc/passwd |
| suid | SUID 提权 | 保持权限执行 |
| sudo | Sudo 提权 | 无密码执行 |
| capabilities | 能力提权 | cap_setuid |

---

## 8. 常见危险二进制

| 二进制 | SUID 利用 | Sudo 利用 |
|--------|----------|----------|
| vim | `:!/bin/sh` | `sudo vim -c ':!/bin/sh'` |
| find | `-exec /bin/sh \;` | `sudo find -exec /bin/sh \;` |
| python | `os.execl()` | `sudo python -c 'import pty;pty.spawn("/bin/sh")'` |
| awk | `system()` | `sudo awk 'BEGIN {system("/bin/sh")}'` |
| nmap | `--interactive` | `sudo nmap --interactive` |
| less | `!/bin/sh` | `sudo less /etc/passwd` |
| more | `!/bin/sh` | `sudo more /etc/passwd` |

---

*文档生成时间: 2026-01-20*
