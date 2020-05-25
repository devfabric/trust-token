package token

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	jwt "github.com/dgrijalva/jwt-go"
)

const (
	//HMAC算法
	JWT_HS256 string = "JWT-HS256" //采用hmac-hs256
	JWT_HS384 string = "JWT-HS384" //采用hmac-hs384
	JWT_HS512 string = "JWT-HS512" //采用hmac-hs512

	//ECDSA算法
	JWT_ES256 string = "JWT-ES256" //采用ecdsa-es256
	JWT_ES384 string = "JWT-ES384" //采用ecdsa-es384
	JWT_ES512 string = "JWT-ES512" //采用ecdsa-es512
)

const (
	TK_TYPE     = JWT_HS256
	TK_EXPIREAT = 86400
	TK_SECRET   = "ABC$1&2oiew3975*4j6k80"

	TK_PRIVATE_ES256 = "configs/ec256-private.pem"
	TK_PUBLIC_ES256  = "configs/ec256-public.pem"

	TK_PRIVATE_ES384 = "configs/ec384-private.pem"
	TK_PUBLIC_ES384  = "configs/ec384-public.pem"

	TK_PRIVATE_ES512 = "configs/ec512-private.pem"
	TK_PUBLIC_ES512  = "configs/ec512-public.pem"
)

type HmacEnc struct {
	Secret string `toml:"secret"` //对等秘钥
}

type EcdsaEnc struct {
	IsVerifier bool   `toml:"isverifier"` //是否仅仅是token校验者
	Private    string `toml:"private"`    //私钥文件路径
	Public     string `toml:"public"`     //公钥文件路径
}

type Config struct {
	Type    string   `toml:"type"`    //token签名算法
	Expires int64    `toml:"expires"` //所有请求token默认过期时间
	Hmac    HmacEnc  `toml:"JWT_HS"`  //hmac加密
	Ecdsa   EcdsaEnc `toml:"JWT_ES"`  //ecdsa加密
}

type CacheCfg struct {
	Type    string //token签名算法
	Method  jwt.SigningMethod
	Expires int64    //过期时间
	Hmac    struct { //hmac加密
		Secret []byte //对等秘钥
	}
	Ecdsa struct { //ecdsa加密
		Private *ecdsa.PrivateKey //私钥文件路径
		Public  *ecdsa.PublicKey  //公钥文件路径
	}
}

func LoadTKConfig(workDir string, confgFile string) (*CacheCfg, *Config, error) {
	path := filepath.Join(workDir, confgFile)
	filePath, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}

	config := new(Config)
	if checkFileIsExist(filePath) { //文件存在
		if _, err := toml.DecodeFile(filePath, config); err != nil {
			return nil, nil, err
		}
	} else {
		config.Type = TK_TYPE
		config.Expires = TK_EXPIREAT
		config.Hmac = HmacEnc{
			Secret: TK_SECRET,
		}
		config.Ecdsa = EcdsaEnc{
			Private: TK_PRIVATE_ES256,
			Public:  TK_PUBLIC_ES256,
		}

		configBuf := new(bytes.Buffer)
		if err := toml.NewEncoder(configBuf).Encode(config); err != nil {
			return nil, nil, err
		}
		err := ioutil.WriteFile(filePath, configBuf.Bytes(), 0666)
		if err != nil {
			return nil, nil, err
		}
	}

	//缓存
	cacheCfg := new(CacheCfg)
	{
		switch config.Type {
		case JWT_ES256:
			cacheCfg.Method = jwt.SigningMethodES256
		case JWT_ES384:
			cacheCfg.Method = jwt.SigningMethodES384
		case JWT_ES512:
			cacheCfg.Method = jwt.SigningMethodES512
		case JWT_HS256:
			cacheCfg.Method = jwt.SigningMethodHS256
		case JWT_HS384:
			cacheCfg.Method = jwt.SigningMethodHS384
		case JWT_HS512:
			cacheCfg.Method = jwt.SigningMethodHS512
		default:
			return nil, nil, errors.New("unknow type encrypt token style")
		}

		if config.Type == JWT_ES256 ||
			config.Type == JWT_ES384 ||
			config.Type == JWT_ES512 {
			if config.Ecdsa.IsVerifier { //仅是token验证者
				//加载公钥
				path := filepath.Join(workDir, config.Ecdsa.Public)
				pubPath, err := filepath.Abs(path)
				if err != nil {
					return nil, nil, err
				}

				if checkFileIsExist(pubPath) {
					cacheCfg.Ecdsa.Public, err = loadPublicKey(pubPath)
					if err != nil {
						return nil, nil, err
					}
				} else {
					return nil, nil, errors.New("ec512-public.pem file does not exist")
				}
			} else {
				//加载私钥
				path := filepath.Join(workDir, config.Ecdsa.Private)
				priPath, err := filepath.Abs(path)
				if err != nil {
					return nil, nil, err
				}

				if checkFileIsExist(priPath) {
					cacheCfg.Ecdsa.Private, err = loadPrivateKey(priPath)
					if err != nil {
						return nil, nil, err
					}
				} else {
					return nil, nil, errors.New("ec512-private.pem file does not exist")
				}

				//加载公钥
				path = filepath.Join(workDir, config.Ecdsa.Public)
				pubPath, err := filepath.Abs(path)
				if err != nil {
					return nil, nil, err
				}

				if checkFileIsExist(pubPath) {
					cacheCfg.Ecdsa.Public, err = loadPublicKey(pubPath)
					if err != nil {
						return nil, nil, err
					}
				} else {
					return nil, nil, errors.New("ec512-public.pem file does not exist")
				}
			}
		} else if config.Type == JWT_HS256 ||
			config.Type == JWT_HS384 ||
			config.Type == JWT_HS512 {
			cacheCfg.Hmac.Secret = []byte(config.Hmac.Secret)
		}

		//加载默认过期时间
		cacheCfg.Expires = config.Expires
		cacheCfg.Type = config.Type
	}

	return cacheCfg, config, nil
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func loadPrivateKey(priFile string) (*ecdsa.PrivateKey, error) {
	private, err := ioutil.ReadFile(priFile)
	if err != nil {
		return nil, err
	}

	ecdsaPriKey, err := jwt.ParseECPrivateKeyFromPEM(private)
	if err != nil {
		return nil, err
	}

	return ecdsaPriKey, nil
}

func loadPublicKey(pubFile string) (*ecdsa.PublicKey, error) {
	public, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, err := jwt.ParseECPublicKeyFromPEM(public)
	if err != nil {
		return nil, err
	}

	return ecdsaPubKey, nil
}

/*
token加密算法:
hmac
hmac-hs256
hmac-hs384
hmac-hs512  采用 默认

ecdsa
ecdsa-es256
ecdsa-es384
ecdsa-es512 采用

TK_EXPIREAT 过期时间默认一天
*/
