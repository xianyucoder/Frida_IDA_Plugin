# Frida_IDA_Plugin
利用frida和IDAPython插件一键过某音fiddler证书检测


## 工具
```
IDA 7.5 
mouyin V21.2.0-
frida 15.1.1
Android 11
fiddler v5.0.20211.51073
```


## 使用方法

```
1.把文件 【bypass_certDet.py】 和 【passplugin】  文件夹放到
  IDA安装目录/plugins/
  
2.启动frida-server

3.调试好fiddler，打开fiddler（此时某音无法上网）

4.提取出Android端 某音的 libsscronet.so，利用IDA32打开

5.快捷键 ctrl+alt+c     或者    IDA手动打开： Edit-Plugins-DYCRTPass 

6.就可以利用fiddler抓包了
```

## 成功示意图
### ida图
![image](https://user-images.githubusercontent.com/50468890/180230296-e18b49e0-bd6c-4ce8-bd26-14eee6dc29f7.png)



### fiddler图
![image](https://user-images.githubusercontent.com/50468890/180229714-c13ad00f-25f4-42f1-88e0-9b38b4d76d2f.png)


## 免责声明
1.若使用者滥用本项目,本人 **无需承担** 任何法律责任.<br />
2.本程序仅供互相学习交流,源码全部开源,**禁止滥用** 和二次**贩卖盈利**. **禁止用于商业用途**


