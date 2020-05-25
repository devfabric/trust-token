package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"code.uni-ledger.com/switch/switch-token/token"
)

func GetWorkDirectory() (string, error) {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return "", err
	}
	return strings.Replace(dir, "\\", "/", -1), nil
}

func main() {
	//获取工作目录
	runDir, err := GetWorkDirectory()
	if err != nil {
		panic(err)
	}

	//token服务对象
	tkSrv, err := token.GetTokenSrv(runDir, "configs/token.toml")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//读取配置
	config := tkSrv.GetConfig()
	fmt.Println(config, "默认配置过期时间:", config.Expires)

	/*
		参数:
			用户名
			机构id
			自定义kv
			接受token客户名(默认switch-directory-chain)
			过期时间(可以为0,默认1天)

		返回:
			token字符串
			过期时间,单位秒
	*/
	fmt.Println("token 申请时间:", time.Now().String())
	token, expires, err := tkSrv.GenerateToken("tom", "org123", map[string]interface{}{"k1": "v1"}, "directory-chain", 2)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	tm := time.Unix(expires, 0)
	fmt.Println("token:", token)
	fmt.Println("过期秒数:", expires)
	fmt.Println("过期本地时间:", tm.String())
	fmt.Println("过期UTC时间:", tm.UTC().String())
	//参数可为空,走默认值
	_, _, err = tkSrv.GenerateToken("alis", "org123", nil, "", 0)

	/*
		参数:
			机构用户名
			机构id
			验证token
		返回:
			nil成功
			其他失败
	*/
	err = tkSrv.VerifyToken("tom", "org123", token)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("token验证通过,未过期")

	time.Sleep(time.Second * 3)
	/*
		参数:
			token字符串
		返回:
			机构用户名
			机构id
			自定义kv
	*/
	uname, orgCode, customKV, err := tkSrv.ParseToken(token, true)
	if err != nil {
		fmt.Println(err.Error()) //"Token is expired"
		//return
	}
	fmt.Println("验证后的token有效数据", uname, orgCode)

	for k, v := range customKV {
		fmt.Println(k, v)
	}

	//不验证token时间以及签名,获取token中的有效数据
	uname, orgCode, customKV, err = tkSrv.ParseToken(token, false)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("不验证,仅获取token有效数据", uname, orgCode)

	for k, v := range customKV {
		fmt.Println(k, v)
	}
}
