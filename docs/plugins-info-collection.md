# Veinmind 信息收集类插件技术分析

本文档涵盖信息收集类插件的深度技术分析。

---

## 1. veinmind-basic - 基础信息收集

**功能概述**: 收集镜像和容器的基础元数据信息。

### 1.1 多运行时适配（适配器模式）

```go
// plugins/go/veinmind-basic/cmd/basic/cli.go:84-174
func scanContainer(c *cmd.Command, container api.Container) error {
    var (
        containerRuntime  event.RuntimeType
        runtimeUniqDesc   string
        mountDetails      []event.MountDetail
        createdTime       int64
    )

    ocispec, err := container.OCISpec()
    if err != nil {
        ocispec = &specs.Spec{}
    }

    // 根据容器类型进行适配
    switch c := container.(type) {
    case *docker.Container:
        // Docker 运行时处理
        containerRuntime = event.Docker
        runtimeUniqDesc = c.Runtime().UniqueDesc()

        config, _ := c.Config()
        createdTime = config.Created.Unix()

        // Docker 特定的挂载信息处理
        for _, mount := range config.MountPoints {
            mountDetails = append(mountDetails, event.MountDetail{
                Destination: mount.Destination,
                Type:        mount.Type,
                Source:      mount.Source,
                Permission: func() string {
                    if mount.Rw { return "rw" }
                    return "ro"
                }(),
                VolumeName: mount.Name,
            })
        }

    case *containerd.Container:
        // 跳过 moby 命名空间（Docker 管理的容器）
        splits := strings.SplitN(c.ID(), "/", 2)
        if len(splits) == 2 && splits[0] == "moby" {
            return nil
        }

        containerRuntime = event.Containerd
        runtimeUniqDesc = c.Runtime().UniqueDesc()

        // Containerd 特定的挂载信息处理
        for _, mount := range ocispec.Mounts {
            permission := "rw"
            for _, option := range mount.Options {
                if option == "ro" {
                    permission = "ro"
                    break
                }
            }
            mountDetails = append(mountDetails, event.MountDetail{
                Destination: mount.Destination,
                Type:        mount.Type,
                Source:      mount.Source,
                Options:     mount.Options,
                Permission:  permission,
            })
        }
    }
}
```

### 1.2 用户/组名映射

```go
// plugins/go/veinmind-basic/cmd/basic/cli.go:196-234
func scanContainer(c *cmd.Command, container api.Container) error {
    // ... 省略部分代码

    // 映射 UID -> 用户名
    entries, err := passwd.ParseFilesystemPasswd(container)
    if err == nil {
        for _, e := range entries {
            uid, _ := strconv.ParseUint(e.Uid, 10, 32)
            if uint32(uid) == ocispec.Process.User.UID {
                rootProcessDetail.Username = e.Username
                break
            }
        }
    }

    // 映射 GID -> 组名
    entries, err := group.ParseFilesystemGroup(container)
    if err == nil {
        for _, e := range entries {
            gid, _ := strconv.ParseUint(e.Gid, 10, 32)
            if uint32(gid) == ocispec.Process.User.GID {
                rootProcessDetail.Groupname = e.GroupName
                break
            }
        }
    }
}
```

### 1.3 特权容器检测

```go
// plugins/go/veinmind-basic/pkg/capability/cap.go:15-50
func IsPrivileged(container api.Container) bool {
    state, err := container.OCIState()
    if err != nil {
        return false
    }

    if state.Pid == 0 {
        return false
    }

    // 读取进程状态文件
    status, err := ioutil.ReadFile(filepath.Join(
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

    // 全 f 表示特权模式
    return strings.HasSuffix(matched[1], "ffffffff")
}
```

### 1.4 镜像信息收集

```go
// plugins/go/veinmind-basic/cmd/basic/cli.go:41-82
func scanImage(c *cmd.Command, image api.Image) error {
    refs, err := image.RepoRefs()
    if err != nil {
        log.Error(err)
    }

    oci, err := image.OCISpecV1()
    if err != nil {
        return err
    }

    evt := &event.Event{
        BasicInfo: &event.BasicInfo{
            ID:         image.ID(),
            Object:     event.NewObject(image),
            Time:       time.Now(),
            Level:      event.None,
            DetectType: event.Image,
            AlertType:  event.BasicImage,
            EventType:  event.Info,
        },
        DetailInfo: &event.DetailInfo{
            AlertDetail: &event.ImageBasicDetail{
                References:  refs,           // 镜像引用
                CreatedTime: oci.Created.Unix(),  // 创建时间
                Env:         oci.Config.Env,      // 环境变量
                Entrypoint:  oci.Config.Entrypoint, // 入口点
                Cmd:         oci.Config.Cmd,      // 命令
                WorkingDir:  oci.Config.WorkingDir, // 工作目录
                Author:      oci.Author,          // 作者
            },
        },
    }

    return reportService.Client.Report(evt)
}
```

### 1.5 容器进程信息收集

```go
// plugins/go/veinmind-basic/cmd/basic/cli.go:238-325
func scanContainer(c *cmd.Command, container api.Container) error {
    // 获取容器内所有进程
    pids, err := container.Pids()
    if err != nil {
        log.Error(err)
    } else {
        for _, pid := range pids {
            p, err := container.NewProcess(pid)
            if err != nil {
                continue
            }

            // 收集进程信息
            cmdline, _ := p.Cmdline()
            cwd, _ := p.Cwd()
            env, _ := p.Environ()
            exe, _ := p.Exe()
            gids, _ := p.Gids()
            uids, _ := p.Uids()
            ppid, _ := p.Ppid()
            nspid, _ := p.Pid()
            hostPid, _ := p.HostPid()
            name, _ := p.Name()
            status, _ := p.Status()
            createTime, _ := p.CreateTime()
            p.Close()

            // 映射用户名和组名
            usernames := mapUsernames(container, uids)
            groupnames := mapGroupnames(container, gids)

            processDetails = append(processDetails, event.ProcessDetail{
                Cmdline:    cmdline,
                Cwd:        cwd,
                Environ:    env,
                Exe:        exe,
                Gids:       gids,
                Groupnames: groupnames,
                Uids:       uids,
                Usernames:  usernames,
                Pid:        nspid,
                Ppid:       ppid,
                HostPid:    hostPid,
                Status:     status,
                Name:       name,
                CreateTime: createTime.Unix(),
            })
        }
    }
}
```

### 1.6 容器基础信息汇总

```go
// plugins/go/veinmind-basic/cmd/basic/cli.go:327-359
evt := &event.Event{
    BasicInfo: &event.BasicInfo{
        ID:         container.ID(),
        Object:     event.NewObject(container),
        Time:       time.Now(),
        Level:      event.Low,
        DetectType: event.Container,
        AlertType:  event.BasicContainer,
        EventType:  event.Info,
    },
    DetailInfo: &event.DetailInfo{
        AlertDetail: &event.ContainerBasicDetail{
            Name:            container.Name(),        // 容器名
            CreatedTime:     createdTime,            // 创建时间
            State:           string(ocistate.Status), // 运行状态
            Runtime:         containerRuntime,       // 运行时类型
            RuntimeUniqDesc: runtimeUniqDesc,        // 运行时描述
            Hostname:        ocispec.Hostname,       // 主机名
            ImageID:         container.ImageID(),    // 镜像 ID
            Privileged:      capability.IsPrivileged(container), // 特权模式
            RootProcess:     rootProcessDetail,      // 根进程信息
            Mounts:          mountDetails,           // 挂载信息
            Processes:       processDetails,         // 进程列表
        },
    },
}
```

---

## 信息收集数据结构

### 镜像信息 (ImageBasicDetail)

| 字段 | 类型 | 说明 |
|------|------|------|
| References | []string | 镜像引用列表 |
| CreatedTime | int64 | 创建时间戳 |
| Env | []string | 环境变量 |
| Entrypoint | []string | 入口点 |
| Cmd | []string | 默认命令 |
| WorkingDir | string | 工作目录 |
| Author | string | 作者 |

### 容器信息 (ContainerBasicDetail)

| 字段 | 类型 | 说明 |
|------|------|------|
| Name | string | 容器名称 |
| CreatedTime | int64 | 创建时间戳 |
| State | string | 运行状态 |
| Runtime | RuntimeType | 运行时类型 |
| Hostname | string | 主机名 |
| ImageID | string | 镜像 ID |
| Privileged | bool | 是否特权 |
| RootProcess | RootProcessDetail | 根进程信息 |
| Mounts | []MountDetail | 挂载列表 |
| Processes | []ProcessDetail | 进程列表 |

### 进程信息 (ProcessDetail)

| 字段 | 类型 | 说明 |
|------|------|------|
| Pid | int32 | 进程 ID |
| Ppid | int32 | 父进程 ID |
| HostPid | int32 | 宿主机进程 ID |
| Name | string | 进程名 |
| Cmdline | string | 命令行 |
| Exe | string | 可执行文件路径 |
| Cwd | string | 工作目录 |
| Status | string | 进程状态 |
| Uids | []int32 | UID 列表 |
| Gids | []int32 | GID 列表 |
| Usernames | []string | 用户名列表 |
| Groupnames | []string | 组名列表 |
| Environ | []string | 环境变量 |
| CreateTime | int64 | 创建时间 |

### 挂载信息 (MountDetail)

| 字段 | 类型 | 说明 |
|------|------|------|
| Source | string | 源路径 |
| Destination | string | 目标路径 |
| Type | string | 挂载类型 |
| Options | []string | 挂载选项 |
| Permission | string | 权限 (ro/rw) |
| VolumeName | string | 卷名称 |

---

## 运行时适配对比

| 特性 | Docker | Containerd |
|------|--------|------------|
| 运行时标识 | `event.Docker` | `event.Containerd` |
| 挂载信息来源 | `config.MountPoints` | `ocispec.Mounts` |
| 创建时间 | `config.Created` | 需从 OCI Spec 获取 |
| 权限字段 | `mount.Rw` (bool) | `mount.Options` ([]string) |
| 卷名称 | `mount.Name` | 不支持 |

---

*文档生成时间: 2026-01-20*
