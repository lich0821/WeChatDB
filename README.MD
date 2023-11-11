# Hack WeChat DB
[偷偷查看微信聊天记录](https://mp.weixin.qq.com/s/nckZTQ0leQLz27vUv4KfGg) 对应的代码。

**⚠️ 仅作技术研究，请勿违法犯罪；也不要将自己的密码和数据库提供给他人，以免隐私受损。**

## 使用方法
### 安装依赖
```sh
pip install -r requirements.txt
```

### 获取密钥
两种方法，一种需要输入微信号；一种需要指定微信版本。

#### 1 通过微信号
感谢 @sanpee 的 [PR](https://github.com/lich0821/WeChatDB/pull/6)，可以无视版本。

```sh
python GetWeChatAesKey.py --id 当前登录的微信号
```

#### 2 直接运行
如果当前微信版本在 `AESKEY_OFFSETS` 或者 `AESKEY_OFFSETS_64` 中（见 [GetWeChatAesKey.py](GetWeChatAesKey.py)），直接运行即可。
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
