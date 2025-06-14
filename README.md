# 密碼工程 期末專案

這是一個金鑰管理伺服器 ( KMS ) 的小實作，負責加密雲端硬碟的存取權限管理

## 使用方式

### CA 自簽憑證
需要先使用 openssl 等工具生成 CA 的憑證，例如：
```
openssl genpkey -algorithm RSA -out keys/ca.key -pkeyopt rsa_keygen_bits:2048 -nodes
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout keys/ca.key -out keys/ca.crt -subj "/C=TW/ST=Taiwan/L=Hsinchu City/O=MyCompany/OU=IT Department/CN=localhost"
```

### 運行
這個專案使用 [uv](https://docs.astral.sh/uv/) 來管理 python 環境\
使用：
```
uv run app.py
```
來自動安裝依賴並執行主程式

## 主要功能
- 分發證書
- 以證書驗證使用者身分
- 防重放攻擊

## 防重放攻擊
### 證書申請
- 新證書：
已存在使用者申請新證書時，需要附帶舊的證書以及新的公鑰
- 證書重發：
相同密鑰的證書重發有五分鐘的冷卻時間，加上伺服器過濾五分鐘前的所有封包

### 證書認證
紀錄每個使用者的證書流水號，每次來存取金鑰時，都會發一張新的證書\
只有封包中證書的流水號與當前使用者紀錄的流水號相同時，才視為有效的證書

## 設計特點
除了每個人有自己的金鑰外，還有一些多人共同持有的金鑰，實現多人共享檔案的功能