# woodwhales-encrypt-tool

> java 加解密工具

## DES 加解密

### 带偏移量的 DES 加解密

DES/CBC/PKCS5Padding 加密：cn.woodwhales.encrypt.DesTool#encryptWithKeyAndIv

DES/CBC/PKCS5Padding 解密：cn.woodwhales.encrypt.DesTool#decryptWithKeyAndIv

### 普通 DES 的加解密

DES/ECB/PACKS5padding 加密：cn.woodwhales.encrypt.DesTool#encryptWithKey

DES/ECB/PACKS5padding 解密：cn.woodwhales.encrypt.DesTool#decryptWithKey

## AES 加解密

### 带偏移量的 AES 加解密

AES/ECB/PKCS5Padding 加密：cn.woodwhales.encrypt.AesTool.encryptWithKey

AES/ECB/PKCS5Padding 解密：cn.woodwhales.encrypt.AesTool.decryptWithKey

### 普通 AES 的加解密

AES/CBC/PKCS5Padding 解密：cn.woodwhales.encrypt.AesTool.encryptWithKeyAndIv

AES/CBC/PKCS5Padding 解密：cn.woodwhales.encrypt.AesTool.decryptWithKeyAndIv
