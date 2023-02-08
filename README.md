# WeChatDB-Rust

用Rust语言编写，使用特征值从微信内存中提取数据库密钥的工具

## 使用方法
### 编译
安装Rust语言编译器，然后执行以下命令：
```bash
cargo build --release
```
编译出的文件在`target/release`目录下

### 运行
```bash
WeChatDB.exe 即可
```

## 原理说明
### 特征值
微信的内存中存在用户的公私钥对，我们通过搜索`-----BEGIN PUBLIC KEY-----`关键字找到其在内存中的位置，
并二次搜索其所在的内存地址，这样我们就可以找到用户信息的上下文。原理参考[1]

### 搜索算法
搜索算法采用Sunday算法，思路来自[2]，可以在O(n)的时间复杂度内完成搜索，原理参考[3]


## 参考
1. https://github.com/x1hy9/WeChatUserDB
2. https://www.jianshu.com/p/2e6eb7386cd3
3. https://github.com/baiyies/CppWeixinHunter