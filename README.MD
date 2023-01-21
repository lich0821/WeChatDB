# Hack WeChat DB
[偷偷查看微信聊天记录](https://mp.weixin.qq.com/s/nckZTQ0leQLz27vUv4KfGg) 对应的代码。

**⚠️ 仅作技术研究，请勿违法犯罪；也不要将自己的密码和数据库提供给他人，以免隐私受损。**

## 使用方法
### 安装依赖
```sh
pip install -r requirements.txt
```

### 获取密钥
```sh
python GetWeChatAesKey.py
```

### 解密数据库
```sh
python CrackWeChatDB.py -p 数据库的完整路径 -k 刚才获取到的密钥
```

解密的数据库在原路径下，以 `.dec.db` 结尾。

欢迎交流：

<center>

![碲矿](碲矿.jpeg)
</center>
