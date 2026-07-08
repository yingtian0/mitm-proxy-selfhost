goの標準ライブラリでtlsを終端するプロキシを実装。
=======
mitm-proxyをgoの標準ライブラリで実装し、tlsを終端します。
これは自身の端末のみを対象としており、悪用の目的はありません。


## 動作確認の最短手順

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout certs/ca.key \
  -out certs/ca.crt \
  -subj "/CN=local mitm demo CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
cp .env.example .env
go run .
```

別ターミナルで:

```bash
curl -v -x http://127.0.0.1:8001 --cacert certs/ca.crt https://example.com/
