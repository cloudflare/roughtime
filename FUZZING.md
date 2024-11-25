# Running go-fuzz tests

```sh
go test -fuzz=FuzzParseRequest ./protocol
go test -fuzz=FuzzVerifyReply ./protocol
```
