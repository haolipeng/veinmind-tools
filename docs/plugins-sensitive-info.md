# Veinmind 敏感信息类插件技术分析

本文档涵盖 2 个敏感信息类插件的深度技术分析。

---

## 1. veinmind-sensitive - 敏感信息扫描

**功能概述**: 基于规则检测敏感信息，采用三级缓存架构优化性能。

### 1.1 三级缓存架构

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

#### 白名单缓存

```go
// plugins/go/veinmind-sensitive/cache/white_path.go
var WhitePath = whitePathCache{...}

func (c *whitePathCache) Contains(path string) bool {
    c.mux.RLock()
    defer c.mux.RUnlock()
    _, ok := c.mem[path]
    return ok
}

func (c *whitePathCache) Add(path string) {
    c.mux.Lock()
    defer c.mux.Unlock()
    c.mem[path] = struct{}{}
}
```

#### 路径规则缓存

```go
// plugins/go/veinmind-sensitive/cache/path_rule.go:9-14
var PathRule = pathRuleCache{
    mux: gmutex.New(),
    mem: make(map[string]map[int64]rule.Rule),
}
```

#### 哈希规则缓存

```go
// plugins/go/veinmind-sensitive/cache/hash_rule.go:9-50
var HashRule = hashRuleCache{
    mux: gmutex.New(),
    mem: make(map[string]map[int64]rule.Rule),
}

func (c *hashRuleCache) Get(key string) (map[int64]rule.Rule, bool) {
    c.mux.RLock()
    defer c.mux.RUnlock()
    val, ok := c.mem[key]
    return val, ok
}

func (c *hashRuleCache) SetOrAppend(key string, r rule.Rule) {
    c.mux.Lock()
    defer c.mux.Unlock()
    if _, ok := c.mem[key]; !ok {
        c.mem[key] = make(map[int64]rule.Rule)
    }
    c.mem[key][r.Id] = r
}
```

### 1.2 正则编译缓存

```go
// plugins/go/veinmind-sensitive/vregex/cache.go:1-34
var regexMap = sync.Map{}

func getRegexp(pattern string) (regex *regexp.Regexp, err error) {
    // 读缓存
    loaded, ok := regexMap.Load(pattern)
    if ok {
        return loaded.(*regexp.Regexp), nil
    }

    // 编译并缓存
    regex, err = regexp.Compile(pattern)
    regexMap.Store(pattern, regex)
    return
}
```

使用 `sync.Map` 实现线程安全的正则表达式缓存，避免重复编译开销。

### 1.3 三维度扫描

```go
// plugins/go/veinmind-sensitive/cmd/scan.go:34-77
func Scan(c *cmd.Command, image api.Image) (err error) {
    conf := rule.SingletonConf()
    eg := errgroup.Group{}
    eg.SetLimit(defaultLimit)

    // 1. 环境变量扫描
    scanEnv(image, conf)

    // 2. Docker History 扫描
    scanDockerHistory(image, conf)

    // 3. 文件系统扫描
    veinfs.Walk(image, "/", func(info *veinfs.FileInfo, err error) error {
        eg.Go(func() error {
            return scanFS(image, info.Path, info, conf)
        })
        return nil
    })

    eg.Wait()
}
```

#### 环境变量扫描

```go
// plugins/go/veinmind-sensitive/cmd/scan.go:81-97
func scanEnv(image api.Image, conf *rule.Config) error {
    ocispec, _ := image.OCISpecV1()

    for _, env := range ocispec.Config.Env {
        for _, r := range conf.Rule {
            if r.Env != "" && vregex.IsMatchString(r.Env, env) {
                envArr := strings.Split(env, "=")
                if len(envArr) == 2 {
                    // 报告环境变量敏感信息
                    reportEvent("env", image, r, envArr[0], envArr[1], ...)
                }
            }
        }
    }
    return nil
}
```

#### Docker History 扫描

```go
// plugins/go/veinmind-sensitive/cmd/scan.go:99-114
func scanDockerHistory(image api.Image, conf *rule.Config) error {
    ocispec, _ := image.OCISpecV1()

    for _, history := range ocispec.History {
        for _, r := range conf.Rule {
            if r.MatchPattern != "" && vregex.IsMatchString(r.MatchPattern, history.CreatedBy) {
                // 报告历史命令敏感信息
                reportEvent("history", image, r, "", "", history.CreatedBy, ...)
            }
        }
    }
    return nil
}
```

#### 文件系统扫描

```go
// plugins/go/veinmind-sensitive/cmd/scan.go:117-220
func scanFS(image api.Image, path string, info *veinfs.FileInfo, conf *rule.Config) error {
    // Level 1: 白名单缓存检查
    if cache.WhitePath.Contains(path) {
        return nil
    }

    // Level 2: 路径规则缓存检查
    rules, ok := cache.PathRule.Get(path)
    if ok {
        if len(rules) > 0 {
            for _, r := range rules {
                reportEvent("file", image, r, ...)
            }
        }
    } else {
        // 检查白名单模式
        for _, pattern := range conf.WhiteList.PathPattern {
            if vregex.IsMatchString(pattern, info.Path) {
                cache.WhitePath.Add(path)
                return nil
            }
        }
        // 检查路径规则
        for _, r := range conf.Rule {
            if r.FilePathPattern != "" && vregex.IsMatchString(r.FilePathPattern, info.Path) {
                cache.PathRule.SetOrAppend(path, r)
                reportEvent("file", image, r, ...)
            }
        }
    }

    // Level 3: 哈希规则缓存检查
    rules, ok = cache.HashRule.Get(info.Sha256)
    if ok {
        for _, r := range rules {
            reportEvent("file", image, r, ...)
        }
        return nil
    }

    // 跳过 ELF 文件
    if info.ELF {
        cache.HashRule.Set(info.Sha256, map[int64]rule.Rule{})
        return nil
    }

    // MIME 类型匹配
    m, _ := mimetype.DetectReader(fp)
    if !gstr.HasPrefix(m.String(), "text/") && !conf.MIMEMap[m.String()] {
        cache.HashRule.Set(info.Sha256, make(map[int64]rule.Rule))
        return nil
    }

    // 内容匹配
    data, _ := io.ReadAll(fp)
    for _, r := range conf.Rule {
        content, loc := vregex.FindIndexWithContextContent(r.MatchPattern, data, defaultContextLength)
        if content != nil {
            cache.HashRule.SetOrAppend(info.Sha256, r)
            reportEvent("file", image, r, ..., string(content), loc)
        }
    }

    return nil
}
```

### 1.4 并发控制

```go
// plugins/go/veinmind-sensitive/cmd/scan.go:22-32
var defaultLimit = 5

func init() {
    limit := runtime.NumCPU() * 5
    if limit > defaultLimit {
        defaultLimit = limit
    }
}

// 使用 errgroup 限制并发
eg := errgroup.Group{}
eg.SetLimit(defaultLimit)

eg.Go(func() error {
    return scanFS(image, info.Path, info, conf)
})

eg.Wait()
```

---

## 2. veinmind-weakpass - 弱密码检测

**功能概述**: 检测容器中的弱密码配置。

### 2.1 Hash 接口策略模式

```go
// plugins/go/veinmind-weakpass/hash/base.go:1-9
type Hash interface {
    ID() string
    Match(hash, guess string) (flag bool, err error)
}
```

#### Shadow 密码格式

```go
// plugins/go/veinmind-weakpass/hash/shadow.go
type Shadow struct{}

func (i *Shadow) ID() string { return "shadow" }

func (i *Shadow) Match(hash, guess string) (flag bool, err error) {
    var pwd Password
    if err := ParsePassword(&pwd, hash); err != nil {
        return false, err
    }
    if _, ok := pwd.Match([]string{guess}); ok {
        return true, nil
    }
    return false, nil
}
```

#### MySQL 密码格式

```go
// plugins/go/veinmind-weakpass/hash/mysql_native_password.go
type MysqlNativePassword struct{}

func (m *MysqlNativePassword) ID() string { return "mysql_native_password" }

func (m *MysqlNativePassword) Match(hash, guess string) (flag bool, err error) {
    // MySQL native password: SHA1(SHA1(password))
    first := sha1.Sum([]byte(guess))
    second := sha1.Sum(first[:])
    computed := strings.ToUpper(hex.EncodeToString(second[:]))
    return computed == strings.ToUpper(hash), nil
}
```

#### 明文密码格式

```go
// plugins/go/veinmind-weakpass/hash/plain.go
type Plain struct{}

func (p *Plain) ID() string { return "plain" }

func (p *Plain) Match(hash, guess string) (flag bool, err error) {
    return hash == guess, nil
}
```

### 2.2 服务注册模式

```go
// plugins/go/veinmind-weakpass/service/register.go:1-24
var modules = make(map[string][]IService)

func Register(key string, p IService) {
    if p == nil {
        panic("Register service is nil")
    }
    modules[key] = append(modules[key], p)
}

func GetModuleByName(modName string) ([]IService, error) {
    m, f := modules[modName]
    if f {
        return m, nil
    }
    return nil, errors.New(fmt.Sprintf("no mod named %s", modName))
}
```

#### 服务接口

```go
// plugins/go/veinmind-weakpass/service/base.go:15-19
type IService interface {
    Name() string
    FilePath() []string
    GetRecords(file io.Reader) (records []model.Record, err error)
}

// 服务与哈希算法映射
var ServiceMatcherMap = make(map[string]string)
```

### 2.3 支持的服务

| 服务 | 配置文件 | 哈希算法 |
|------|---------|---------|
| SSH | `/etc/shadow` | shadow |
| MySQL5 | `mysql.user` 表 | mysql_native_password |
| MySQL8 | `mysql.user` 表 | caching_sha2_password |
| Redis | `redis.conf` | plain |
| Tomcat | `tomcat-users.xml` | plain |
| vsftpd | `/etc/shadow` | shadow |
| proftpd | `/etc/shadow` | shadow |

### 2.4 tunny 线程池并发爆破

```go
// plugins/go/veinmind-weakpass/utils/utils.go:21-145
func StartModule(config model.Config, fs api.FileSystem, modname string, marco map[string]string) (results []model.WeakpassResult, err error) {
    mods, _ := service.GetModuleByName(modname)

    for _, mod := range mods {
        hash, _ := service.GetHash(mod.Name())

        // 加载字典
        var finalDict []string
        finalDict = append(finalDict, service.GetDict(modname)...)
        if config.Dictpath != "" {
            // 用户自定义字典
            f, _ := os.Open(config.Dictpath)
            scanner := bufio.NewScanner(f)
            for scanner.Scan() {
                finalDict = append(finalDict, scanner.Text())
            }
        }

        // 创建线程池
        var weakpassResultsLock sync.Mutex
        pool := tunny.NewFunc(config.Thread, func(opt interface{}) interface{} {
            bruteOpt := opt.(model.BruteOption)

            match, _ := hash.Match(bruteOpt.Records.Password, bruteOpt.Guess)
            if match {
                weakpassResultsLock.Lock()
                WeakpassResults = append(WeakpassResults, model.WeakpassResult{
                    Username:    bruteOpt.Records.Username,
                    Password:    bruteOpt.Guess,
                    ServiceType: service.GetType(mod),
                })
                weakpassResultsLock.Unlock()
                return true
            }
            return false
        })
        defer pool.Close()

        // 爆破
        records, _ := mod.GetRecords(file)
        for _, item := range records {
            for _, guess := range finalDict {
                // 宏替换
                guess = strings.Replace(guess, "${image_name}", marco["image_name"], -1)
                guess = strings.Replace(guess, "${module_name}", marco["module_name"], -1)

                match, _ := pool.ProcessTimed(model.BruteOption{
                    Records: item,
                    Guess:   guess,
                }, 5*time.Second)

                if v, ok := match.(bool); ok && v {
                    break  // 找到密码，跳过后续猜测
                }
            }
        }
    }
}
```

### 2.5 字典宏替换

```go
// 支持的宏
guess = strings.Replace(guess, "${image_name}", marco["image_name"], -1)
guess = strings.Replace(guess, "${module_name}", marco["module_name"], -1)
```

这允许字典中使用动态值，如：
- `${image_name}123` → `nginx123`
- `${module_name}@2024` → `mysql@2024`

---

## 敏感信息类插件对比

| 特性 | veinmind-sensitive | veinmind-weakpass |
|------|-------------------|------------------|
| 检测目标 | 敏感信息泄露 | 弱密码配置 |
| 扫描范围 | 环境变量 + History + 文件 | 配置文件 |
| 缓存机制 | 三级缓存 | 无 |
| 并发控制 | errgroup.SetLimit | tunny.Pool |
| 规则格式 | 正则表达式 | 密码字典 |
| 扩展性 | 规则配置 | 服务注册 |

---

*文档生成时间: 2026-01-20*
