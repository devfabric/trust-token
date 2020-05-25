package token

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

/*

client                                                server
uname/pwd/orgcode ----------------------------------->  去用户中心判断机构id下的用户uname和pwd 是否正确,正确下生成token
													  hmac对等秘钥加密{uname,orgcode,time,seqnum} = token  or ecdsa私钥加密{uname,orgcode,time,seqnum} = token
			 <--------------------------------------- token (call GenerateToken)

校验:
hmac对等秘钥校验(token,uname,orgcode) (call VerifyToken)
OR
ecdsa公钥校验(token,uname,orgcode) (call VerifyToken)
或者调用ParseToken 获取uname,orgcode 内部比较
*/

type CustomClaims struct {
	UserName string                 `json:"uname"`
	OrgCode  string                 `json:"orgcode"`
	CustomKV map[string]interface{} `json:"customkv"`
	jwt.StandardClaims
}

type TokenSrv struct {
	config   *CacheCfg
	fdConfig *Config
}

/*
GetTokenSrv token服务初始化
参数:
workDir 工作目录路径
configFile 配置文件相对工作目录路径
返回:
成功返回TokenSrv,nil
失败返回nil,error
*/
func GetTokenSrv(workDir string, configFile string) (*TokenSrv, error) {
	var (
		err error
		tk  = &TokenSrv{}
	)

	tk.config, tk.fdConfig, err = LoadTKConfig(workDir, configFile)
	if err != nil {
		return nil, err
	}

	return tk, nil
}

/*
GenerateToken 生成token
参数:
userName 用户名
orgCode 机构id
customKV 可放置token的自定义kv值,可为nil
audience 接受token客户端名称,默认switch-directory-chain
expires token过期时间,如果为0,则默认1天
返回:
成功返回token,过期时间(单位秒),nil
失败返回"",0,error
*/
func (tk *TokenSrv) GenerateToken(userName, orgCode string, customKV map[string]interface{}, audience string, expires int64) (string, int64, error) {
	var (
		err         error
		duration    time.Duration
		tokenAccess string
	)

	if expires <= 0 {
		duration = time.Duration(tk.config.Expires) * time.Second
	} else {
		duration = time.Duration(expires) * time.Second
	}

	if audience == "" {
		audience = "switch-directory-chain"
	}

	claims := &CustomClaims{
		userName,
		orgCode,
		customKV, //自定义kv,可为空
		jwt.StandardClaims{
			Audience:  audience,                                     //标识token的接收者.
			ExpiresAt: time.Now().Add(duration).Unix(),              //过期时间
			Id:        strconv.FormatInt(time.Now().UnixNano(), 10), //自定义的id号,随机数据,扰乱token数值
			IssuedAt:  time.Now().Unix(),                            //签名发行时间.
			Issuer:    "RAC",                                        //签名的发行者.
			Subject:   "client",                                     //签名面向的用户
		},
	}

	token := jwt.NewWithClaims(tk.config.Method, claims)
	if tk.config.Type == JWT_HS256 ||
		tk.config.Type == JWT_HS384 ||
		tk.config.Type == JWT_HS512 {
		tokenAccess, err = token.SignedString([]byte(tk.config.Hmac.Secret))
		if err != nil {
			return "", 0, err
		}
	} else if tk.config.Type == JWT_ES256 ||
		tk.config.Type == JWT_ES384 ||
		tk.config.Type == JWT_ES512 {
		tokenAccess, err = token.SignedString(tk.config.Ecdsa.Private)
		if err != nil {
			return "", 0, err
		}
	}

	return tokenAccess, claims.ExpiresAt, nil
}

/*
VerifyToken 验证token
参数:
userName 用户名
orgCode 机构ID
tokenStr base64编码的token
返回:
成功返回nil
失败返回error
*/
func (tk *TokenSrv) VerifyToken(userName, orgCode, tokenStr string) error {
	var (
		err   error
		token *jwt.Token
	)

	if tk.config.Type == JWT_HS256 ||
		tk.config.Type == JWT_HS384 ||
		tk.config.Type == JWT_HS512 {
		token, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(tk.config.Hmac.Secret), nil
		})

	} else if tk.config.Type == JWT_ES256 ||
		tk.config.Type == JWT_ES384 ||
		tk.config.Type == JWT_ES512 {
		token, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return tk.config.Ecdsa.Public, nil
		})
	}

	if err != nil {
		return err
	} else {
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			uname, isUname := claims["uname"]
			orgCode, isOrgCode := claims["orgcode"]
			if isUname && isOrgCode && uname == userName && orgCode == orgCode {
				return nil
			} else {
				return errors.New("Token does not match uname or orgid")
			}
		} else {
			return errors.New("token is invalid")
		}
	}
}

/*
ParseToken 判断token是否过期并获取token中的用户和机构
参数:
tokenStr token字符串
isVerify true验证过期时间和签名,否则不验证,仅获取其中的有效数据
返回:
成功:用户名,机构id,nil
失败:"","",error
*/
func (tk *TokenSrv) ParseToken(tokenString string, isVerify bool) (string, string, map[string]interface{}, error) {
	var (
		err      error
		token    *jwt.Token
		uname    string
		orgCode  string
		customKV map[string]interface{}
	)

	if isVerify { //验证token时间以及签名数据
		if tk.config.Type == JWT_HS256 ||
			tk.config.Type == JWT_HS384 ||
			tk.config.Type == JWT_HS512 {
			token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(tk.config.Hmac.Secret), nil
			})
		} else if tk.config.Type == JWT_ES256 ||
			tk.config.Type == JWT_ES384 ||
			tk.config.Type == JWT_ES512 {
			token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return tk.config.Ecdsa.Public, nil
			})
		}

		if err != nil {
			return "", "", nil, err
		} else {
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				if unameObj, ok := claims["uname"]; ok {
					uname = unameObj.(string)
				}
				if orgCodeObj, ok := claims["orgcode"]; ok {
					orgCode = orgCodeObj.(string)
				}
				if customKVObj, ok := claims["customkv"]; ok {
					customKV = customKVObj.(map[string]interface{})
				}
				return uname, orgCode, customKV, nil
			} else {
				return "", "", nil, errors.New("token is invalid")
			}
		}
	}

	//不验证token时间有效性以及签名数据--仅解析
	jwtToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", "", nil, err
	}

	if myClaims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		if unameObj, ok := myClaims["uname"]; ok {
			uname = unameObj.(string)
		}
		if orgCodeObj, ok := myClaims["orgcode"]; ok {
			orgCode = orgCodeObj.(string)
		}
		if customKVObj, ok := myClaims["customkv"]; ok {
			customKV = customKVObj.(map[string]interface{})
		}
		return uname, orgCode, customKV, nil
	}
	return "", "", nil, errors.New("token cannot be forced to MapClaims type")
}

func (tk *TokenSrv) GetConfig() *Config {
	return tk.fdConfig
}
