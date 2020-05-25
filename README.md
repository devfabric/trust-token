```
token 生成与验证(hmac256和椭圆曲线两种token签名方式,token直接在client端验证有效性)

客户端使用用户名\密码\机构ID 去server端获取token:

client                                                server
uname/pwd/orgid ----------------------------------->去用户中心判断机构id下的用户uname和pwd 是否正确,正确下生成token
                                                    hmac对等秘钥加密{uname,orgid,time,seqnum} = token  or ecdsa私钥加密{uname,orgid,time,seqnum} = token
<----------------------------------------------------token (call GenerateToken)

校验:
hmac对等秘钥校验(token,uname,orgid) (call VerifyToken)
OR
ecdsa公钥校验(token,uname,orgid) (call VerifyToken)
或者调用ParseToken 获取uname,orgid 内部比较

```