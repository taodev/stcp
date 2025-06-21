# STCP

STCP (Secure TCP) 是一个基于Go语言的安全TCP连接库，提供加密和压缩功能，适用于需要安全传输的网络应用。

## 特性

- **安全性**：使用AES-GCM加密算法保证数据传输安全
- **高效性**：集成Snappy压缩算法提高传输效率
- **易用性**：API设计简洁，易于集成到现有项目
- **可靠性**：完善的错误处理和超时机制
- **可观测性**：内置数据传输统计功能

## 安装

```bash
go get github.com/taodev/stcp
```

## 快速开始

### 服务端

```go
server, err := stcp.Listen("tcp", "127.0.0.1:8080", &stcp.Config{
    Password: "your-secure-password",
})
if err != nil {
    panic(err)
}
defer server.Close()

conn, err := server.Accept()
if err != nil {
    panic(err)
}
if err = conn.(*stcp.Conn).Handshake(); err != nil {
    conn.Close()
    panic(err)
}

// 使用conn进行读写操作
```

### 客户端

```go
client, err := stcp.Dial("tcp", "127.0.0.1:8080", &stcp.Config{
    Password: "your-secure-password",
})
if err != nil {
    panic(err)
}
defer client.Close()

// 使用client进行读写操作
```

## 性能基准测试

项目包含了多种加密和压缩组合的基准测试，可以通过以下命令运行：

```bash
go run examples/benchmark/main.go
```

## 高级用法

### 自定义配置

```go
config := &stcp.Config{
    Password: "your-secure-password",
    HandshakeTimeout: 10 * time.Second,
    // 其他配置项...
}
```

### 性能统计

```go
// 获取连接的读写统计信息
inRead, inWrite, outRead, outWrite := client.Stat()
fmt.Printf("入站读取: %dMB, 入站写入: %dMB, 出站读取: %dMB, 出站写入: %dMB\n",
    inRead/(1024*1024), inWrite/(1024*1024), outRead/(1024*1024), outWrite/(1024*1024))
```

## 实现细节

STCP使用以下技术确保安全和高效：

1. **加密**：使用AES-GCM模式进行加密，提供认证加密保护
2. **压缩**：使用Snappy算法进行数据压缩，减少传输数据量
3. **握手认证**：实现安全的握手协议，确保连接双方身份
4. **性能优化**：针对不同场景优化读写性能

## 许可证

[MIT](LICENSE)