将AES算法封装成python可用的dll库

AES算法参考：
http://www.gladman.me.uk/
http://brgladman.org/oldsite/cryptography_technology/index.php


导出的AES算法
1.newAES
	生成AES对象
2.setkey
	重设密码key
3.encode
	加密
4.decode
	解密


python脚本
1.MyAESObject.py
	对导出的pyd库进行封装，封装的对象是MyAESObject
2.TestAESObject.py
	对MyAESObject.py的测试
3.AESEncode.py
	进行文件夹的加密，需要制定原目录和加密后的目的目录
	# 工作原理：
	# 删除目的文件目录下的文件
	# 复制原文件目录至目的文件目录
	# 加密目的文件目录下的文件



工程：TestAES
是对GladmanAES的简单测试
