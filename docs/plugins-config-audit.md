# Veinmind 配置审计类插件技术分析

本文档涵盖 2 个配置审计类插件的深度技术分析。

---

## 1. veinmind-iac - IaC 安全扫描

**功能概述**: 使用 OPA/Rego 策略引擎扫描 Dockerfile 和 Kubernetes 配置。

### 1.1 OPA/Rego 策略引擎

```go
// plugins/go/veinmind-iac/pkg/scanner/scanner.go:25-99
type Scanner struct {
    QueryPre string
    Policies map[string]*ast.Module
}

func (bs *Scanner) Scan(ctx context.Context, iacFile api.IAC) ([]Result, error) {
    // 1. 获取解析器
    parseHandle := parser.NewParser(iacFile)
    if parseHandle == nil {
        return nil, errors.New("un support iac type")
    }

    // 2. 加载规则
    bs.LoadRules(iacFile.Type)

    // 3. 解析文件
    file, _ := os.Open(iacFile.Path)
    input, _ := parseHandle(file, iacFile.Path)

    // 4. 编译策略
    compiler := ast.NewCompiler()
    compiler.Compile(bs.Policies)
    if compiler.Failed() {
        return nil, compiler.Errors
    }

    // 5. 执行 OPA 查询
    options := []func(*rego.Rego){
        rego.Query(bs.QueryPre + iacFile.Type.String()),
        rego.Compiler(compiler),
        rego.Input(input),
    }
    res, _ := bs.runOPA(ctx, options...)

    // 6. 解析结果
    value := res.Value.(map[string]interface{})
    for _, v := range value["risks"].([]interface{}) {
        var d = struct {
            Risk
            Rule
        }{}
        mapstructure.Decode(v, &d)
        formatResult = append(formatResult, Result{
            Risks: []Risk{d.Risk},
            Rule:  &d.Rule,
        })
    }
    return formatResult, nil
}
```

### 1.2 OPA 查询执行

```go
// plugins/go/veinmind-iac/pkg/scanner/scanner.go:137-152
func (bs *Scanner) runOPA(ctx context.Context, options ...func(r *rego.Rego)) (*rego.ExpressionValue, error) {
    r := rego.New(options...)

    // 执行查询
    queryResult, err := r.Eval(ctx)
    if err != nil {
        return nil, err
    }

    if len(queryResult) == 0 || len(queryResult[0].Expressions) == 0 {
        return nil, errors.New("扫描结果异常")
    }

    return queryResult[0].Expressions[0], nil
}
```

### 1.3 规则加载

```go
// plugins/go/veinmind-iac/pkg/scanner/scanner.go:101-135
func (bs *Scanner) LoadRules(fileType api.IACType) error {
    return bs.load(fileType.String())
}

func (bs *Scanner) load(path string) error {
    entries, _ := rules.RegoFile.ReadDir(filepath.ToSlash(path))

    for _, entry := range entries {
        if entry.IsDir() {
            bs.load(entry.Name())  // 递归加载子目录
        } else {
            absolutePath := strings.Join(append([]string{path}, entry.Name()), "/")

            // 跳过已加载的规则
            if _, ok := bs.Policies[absolutePath]; ok {
                continue
            }

            // 读取并解析 Rego 模块
            data, _ := fs.ReadFile(rules.RegoFile, absolutePath)
            module, _ := ast.ParseModuleWithOpts(absolutePath, string(data), ast.ParserOptions{})
            bs.Policies[absolutePath] = module
        }
    }
    return nil
}
```

### 1.4 Dockerfile AST 解析

```go
// plugins/go/veinmind-iac/pkg/parser/parser.go:28-94
type DockerFileInput struct {
    Cmd       string   // 指令: FROM, RUN, COPY 等
    SubCmd    string   // 子指令 (用于 ONBUILD)
    Flags     []string // ��志: --from, --chown 等
    Value     []string // 值
    Original  string   // 原始文本
    JSON      bool     // 是否为 JSON 格式
    Stage     int      // 构建阶段索引
    Path      string   // 文件路径
    StartLine int      // 起始行号
    EndLine   int      // 结束行号
}

func dockerfile(file *os.File, path string) (interface{}, error) {
    // 使用 moby/buildkit 解析器
    docker, _ := parser.Parse(file)

    var ret []DockerFileInput
    var stageIndex int

    for _, child := range docker.AST.Children {
        child.Value = strings.ToLower(child.Value)
        instr, _ := instructions.ParseInstruction(child)

        // 处理 FROM 指令，记录构建阶段
        if _, ok := instr.(*instructions.Stage); ok {
            stageIndex++
        }

        cmd := DockerFileInput{
            Cmd:       child.Value,
            Original:  child.Original,
            Flags:     child.Flags,
            Stage:     stageIndex,
            Path:      path,
            StartLine: child.StartLine,
            EndLine:   child.EndLine,
        }

        // 处理 ONBUILD 指令的子命令
        if child.Next != nil && len(child.Next.Children) > 0 {
            cmd.SubCmd = child.Next.Children[0].Value
            child = child.Next.Children[0]
        }

        cmd.JSON = child.Attributes["json"]
        for n := child.Next; n != nil; n = n.Next {
            cmd.Value = append(cmd.Value, n.Value)
        }
        ret = append(ret, cmd)
    }

    return ret, nil
}
```

### 1.5 Kubernetes YAML 解析

```go
// plugins/go/veinmind-iac/pkg/parser/parser.go:96-157
type KubernetesInput struct {
    ApiVersion      string      `yaml:"apiVersion" json:"apiVersion"`
    Path            string      `yaml:"path" json:"Path"`
    Kind            string      `yaml:"kind" json:"kind"`
    Meta            interface{} `yaml:"metadata" json:"metadata"`
    Spec            interface{} `yaml:"spec" json:"spec"`
    SecurityContext interface{} `yaml:"securityContext" json:"securityContext"`
    Privileged      interface{} `yaml:"privileged" json:"privileged"`
    Capabilities    interface{} `yaml:"capabilities" json:"capabilities"`
    HostPID         bool        `yaml:"hostPID" json:"hostPID"`
    Data            map[string]string `yaml:"data" json:"data"`
}

func kubernetes(file *os.File, path string) (interface{}, error) {
    res := make([]*KubernetesInput, 0)

    data, _ := io.ReadAll(file)

    kubernetesInput := &KubernetesInput{}
    yaml.Unmarshal(data, &kubernetesInput)
    kubernetesInput.Path = path

    // 处理 ConfigMap 中嵌套的配置
    if kubernetesInput.Data != nil {
        for _, value := range kubernetesInput.Data {
            if strings.HasPrefix(value, "apiVersion") {
                // 递归解析嵌套配置
                kubernetesTempInput := &KubernetesInput{}
                yaml.Unmarshal([]byte(value), &kubernetesTempInput)
                kubernetesTempInput.Path = path
                res = append(res, kubernetesTempInput)
            }
        }
    } else {
        res = append(res, kubernetesInput)
    }

    return res, nil
}
```

### 1.6 解析器工厂

```go
// plugins/go/veinmind-iac/pkg/parser/parser.go:15-25
type parseHandle func(file *os.File, path string) (interface{}, error)

func NewParser(iacFile api.IAC) parseHandle {
    switch iacFile.Type {
    case api.Dockerfile:
        return dockerfile
    case api.Kubernetes:
        return kubernetes
    }
    return nil
}
```

### 1.7 Rego 规则示例

#### Dockerfile 规则

```rego
# 检测 root 用户运行
package dockerfile

deny[result] {
    input[i].Cmd == "user"
    input[i].Value[0] == "root"
    result := {
        "msg": "Running as root is not recommended",
        "severity": "medium",
        "line": input[i].StartLine
    }
}

# 检测不安全的 RUN 命令
deny[result] {
    input[i].Cmd == "run"
    contains(input[i].Original, "curl")
    contains(input[i].Original, "|")
    contains(input[i].Original, "sh")
    result := {
        "msg": "Avoid piping curl output to shell",
        "severity": "high",
        "line": input[i].StartLine
    }
}
```

#### Kubernetes 规则

```rego
# 检测特权容器
package kubernetes

deny[result] {
    input[_].Spec.Containers[_].SecurityContext.Privileged == true
    result := {
        "msg": "Privileged container detected",
        "severity": "critical"
    }
}

# 检测 hostPID
deny[result] {
    input[_].HostPID == true
    result := {
        "msg": "hostPID is enabled",
        "severity": "high"
    }
}
```

---

## 2. veinmind-unsafe-mount - 不安全挂载检测

**功能概述**: 检测容器中的危险挂载配置。

### 2.1 OCI Spec 挂载信息解析

```go
// plugins/go/veinmind-unsafe-mount/pkg/engine/detect.go:13-52
const DetectType = "UnsafeMount"

func DetectContainerUnsafeMount(container api.Container) (events []event.Event, err error) {
    // 获取 OCI Spec
    spec, err := container.OCISpec()
    if err != nil {
        return nil, err
    }

    // 遍历挂载点
    for _, mount := range spec.Mounts {
        for _, pattern := range UnsafeMountPaths {
            matched, err := filepath.Match(pattern, mount.Source)
            if err != nil {
                continue
            }

            if matched {
                events = append(events, event.Event{
                    BasicInfo: &event.BasicInfo{
                        ID:         container.ID(),
                        Object:     event.NewObject(container),
                        Source:     "veinmind-unsafe-mount",
                        Time:       time.Now(),
                        Level:      event.High,
                        DetectType: event.Container,
                        EventType:  event.Risk,
                        AlertType:  DetectType,
                    },
                    DetailInfo: &event.DetailInfo{
                        AlertDetail: &event.UnSafeMountDetail{
                            Mount: event.MountEvent{
                                Source:      mount.Source,
                                Destination: mount.Destination,
                                Type:        mount.Type,
                            },
                        },
                    },
                })
            }
        }
    }
    return
}
```

### 2.2 危险路径模式

```go
// plugins/go/veinmind-unsafe-mount/pkg/engine/unsafe.go:3-24
var UnsafeMountPaths = []string{
    // 系统目录
    "/",
    "/root",
    "/etc",
    "/boot",
    "/var",
    "/proc",
    "/bin",
    "/sys",

    // 容器运行时 Socket
    "/var/run/docker.sock",
    "/run/containerd.sock",
    "/var/run/crio/crio.sock",

    // Kubernetes 相关
    "/var/lib/kubelet",
    "/var/lib/kubelet/pki",
    "/etc/kubernetes",
    "/etc/kubernetes/manifests",
}
```

### 2.3 风险分类

| 挂载路径 | 风险类型 | 说明 |
|---------|---------|------|
| `/` | 容器逃逸 | 完全访问宿主机文件系统 |
| `/var/run/docker.sock` | 容器逃逸 | 控制 Docker 守护进程 |
| `/run/containerd.sock` | 容器逃逸 | 控制 Containerd |
| `/proc` | 信息泄露 | 访问宿主机进程信息 |
| `/etc` | 配置篡改 | 修改系统配置 |
| `/var/lib/kubelet` | K8s 逃逸 | 访问 Kubelet 凭证 |

### 2.4 主入口

```go
// plugins/go/veinmind-unsafe-mount/cmd/cli.go:32-50
func scanContainer(c *cmd.Command, container api.Container) error {
    log.Infof("start scan container unsafe mount: %s", container.ID())

    evts, err := engine.DetectContainerUnsafeMount(container)
    if err != nil {
        return err
    }

    for _, evt := range evts {
        err := reportService.Client.Report(&evt)
        if err != nil {
            log.Error(err)
            continue
        }
    }

    return nil
}
```

---

## 配置审计类插件对比

| 特性 | veinmind-iac | veinmind-unsafe-mount |
|------|-------------|----------------------|
| 检测目标 | IaC 配置文件 | 运行时挂载配置 |
| 扫描对象 | Dockerfile / K8s YAML | 容器 OCI Spec |
| 规则引擎 | OPA/Rego | 路径匹配 |
| 扫描阶段 | 构建前 (Shift Left) | 运行时 |
| 扩展性 | Rego 规则文件 | 代码修改 |
| 规则数量 | 50+ 内置规则 | ~20 危险路径 |

---

## Rego 规则编写指南

### 基本结构

```rego
package <type>  # dockerfile 或 kubernetes

# 拒绝规则
deny[result] {
    # 条件判断
    <condition>

    # 返回结果
    result := {
        "msg": "<message>",
        "severity": "<low|medium|high|critical>",
        "line": <line_number>
    }
}
```

### 常用模式

#### 检测特定指令

```rego
deny[result] {
    input[i].Cmd == "run"
    contains(input[i].Original, "apt-get")
    not contains(input[i].Original, "--no-install-recommends")
    result := {...}
}
```

#### 检测缺失指令

```rego
deny[result] {
    not user_defined
    result := {"msg": "No USER instruction found"}
}

user_defined {
    input[_].Cmd == "user"
}
```

#### 检测嵌套属性

```rego
deny[result] {
    container := input[_].Spec.Containers[_]
    container.SecurityContext.RunAsRoot == true
    result := {...}
}
```

---

*文档生成时间: 2026-01-20*
