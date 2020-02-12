---
title: Apache Shiro Padding Oracle反序列化漏洞分析（上）
description: 尝试了很久，才敢说明白了Shiro Padding Oracle反序列化漏洞的基本原理，内容有点多，分上下两篇分析一下
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 背景
其实去年11月就开始有Apache Shiro Padding Oracle远程命令执行漏洞的公告满天飞

来源于[Shiro的issue 721](https://issues.apache.org/jira/browse/SHIRO-721)

那时候一是因为对Shiro完全不懂，没有学习过，二是稍看一些分析文章比较复杂，三是使用PoC测试，暴破要很久，所以就对业务版本检测加上对rememberMe的cookie的搜索来用升级Shiro的方式修复漏洞，没有好好分析

因为中间包括一些对Spring历史漏洞的分析，然后这个Shiro漏洞本身比较复杂，网上一些分析文章其实都是复现，再有一些对Padding Oracle的讲解不详细，一夜之间很多分析文章都是默认大家都知道Padding Oracle一样，对很多细节都不讲，所以学习周期有点漫长，加上断断续续学，所以今天才写文章记录

因为这是少见的框架漏洞和密码学有关系，所以要好好讲讲

虽然很多说的是Apache Shiro Padding Oracle漏洞，但是RCE要执行需要Padding Oracle漏洞和反序列化漏洞都满足

所以上篇我们讲一讲已知的反序列化漏洞，讲解`rememberMe`的Cookie的编解码过程和里面的`AES-128-CBC`，为下篇讲解Padding Oracle漏洞打基础

### 0x01 Shiro框架学习
我以前没有用过Shiro框架，所以我需要先学习一下，看一看[慕课网视频学Shiro](https://www.imooc.com/learn/977)

maven依赖

```
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.4.0</version>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-web</artifactId>
    <version>1.4.0</version>
</dependency>
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>RELEASE</version>
</dependency>
```

`resources/user.ini`

```
[users]
mark=123456,admin
[roles]
admin=user:delete,user:add
```

`iniRealmTest.java`

```
package io.github.milkfr;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class iniRealmTest {

    @Test
    public void testAuthentication() {
        IniRealm iniRealm = new IniRealm("classpath:user.ini");

        // 1. 构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(iniRealm);

        // 2. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("mark", "123456");
        subject.login(token);

        System.out.println(token);
        System.out.println("isAuthenticated:" + subject.isAuthenticated());
        subject.checkRole("admin");
        subject.checkPermission("user:delete");
        subject.checkPermission("user:add");
    }
}
```

这是一个简单的例子，可以尝试把Role和Permission的检测值替换，会报错，正常情况测试成功

简单来讲，这个是RBAC的全部了

真的，我觉得比起Spring Security来讲简直太人性化了

而且和[RBAC论文](https://www.profsandhu.com/articles/advcom/adv_comp_rbac.pdf)中用到的专业名字完全一样，比如`Subject`

一看就对Shiro好感度爆棚

然后我们看一下和漏洞有关的Cookie的RememberMe功能

```
package io.github.milkfr;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.junit.Test;

public class iniRealmTest {

    @Test
    public void testAuthentication() {
        IniRealm iniRealm = new IniRealm("classpath:user.ini");
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        simpleCookie.setMaxAge(2592000);
        cookieRememberMeManager.setCookie(simpleCookie);
        cookieRememberMeManager.setCipherKey("ZHANGXIAOHEI_CAT".getBytes());

        // 1. 构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(iniRealm);
        defaultSecurityManager.setRememberMeManager(cookieRememberMeManager);

        // 2. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("mark", "123456");
        token.setRememberMe(true);
        subject.login(token);

        System.out.println("isAuthenticated:" + subject.isAuthenticated());
        subject.checkRole("admin");
        subject.checkPermission("user:delete");
        subject.checkPermission("user:add");
    }
}
```

上面这段代码并不能运行，因为没有webapp，只是了解一下Cookie的RememberMe功能，看了代码就能有个大致的印象，为下文做准备

### 0x02 Shiro RememberMe反序列化漏洞 
[Shiro-issue-550](https://issues.apache.org/jira/browse/SHIRO-550)官方说明

之所以要先说这个漏洞，是因为2016年Shiro的Cookie的RememberMe功能就爆出过反序列化漏洞，简单来说，就是RememberMe记录了序列化后的Java对象，服务端反序列化的过程中触发漏洞

我们说有反序列化的地方就有漏洞，只不过不一定有gadget，不一定可以利用，而Shiro的Cookie RememberMe的反序列化之所以不能利用，因为它对序列化后的对象进行一次AES加密，在没有密钥的情况下，就不可以客户端加密明文，服务端解密密文后执行反序列化操作，也就是AES的密钥不破，用户就无法操作Cooke的RememberMe，而一旦AES的密钥被破，客户就是可以操作Cookie中序列化的值，任意控制序列化的数据，结合gadget造成反序列化漏洞

Shiro-550就是因为AES的密钥硬编码在框架中，导致密钥泄漏

做个实验

#### 搭建环境
```
# 拉取镜像到本地
$ docker pull medicean/vulapps:s_shiro_1
# 启动环境
$ docker run -d -p 8060:8080 medicean/vulapps:s_shiro_1
```

#### 获取Cookie
访问`127.0.0.1:8060`获取cookie中的RememberMe

```
rememberMe=uRzepnTa0PapPGCg4zHb79mlQ1O2UQEmAhM4IsqPkeBUkMqMEhhGNVdb+gkYbiNBLXgMyEoYF7kb0TFMlvzUobAM16o75Gw9Yd0dnLqkaHc1iw/8SmWyFKdBRLp8g+1Bng3jf8j6UQ+iTV5eR1xYBoCYA/0VhcKIV4p3du5cG7mqpUCuXldUeLS15QDfsXiL3aA5Zx8ymkXqdbPUDgcdVyIDxzNXDsXCJLKQqyeKFlYxBbSEJs14v9f+X/xRTx67AlXsIddMeS1LSNvUY4qS2qSy4GiP5FzcXROKYf8uXWTcS7DRNGusRJ13d7UPkGSO9gFWqVafBGSyeVehUp7q42ckbPMpBlMsv8GQ7TGIsx+eATBhNQNcc9JORwziVLs5Mg/EtYeXbxRnyri/9ylnIA+GvlyO8B8UVmYdPcmb7KU/k61Pb6pMig2YL75g7tnUkshKB399/aiJec5ZvbwGLa46oIAQ8qP+XoD7la+mRY/sfwyMTGOy3KqquAL5e4tb
```

#### 解密Cookie
已知硬编码的AES的密钥为base64后的`kPH+bIxk5D2deZiIxcaaaA==`，因为没有IV，所以假设IV为空

```
$ pip install pycryptodome
$ ipython
# 赋值密文
In [1]: c_text = "uRzepnTa0PapPGCg4zHb79mlQ1O2UQEmAhM4IsqPkeBUkMqMEhhGNVdb+gkYbiNBLXgMyEoYF7kb0TFMlvzUob
   ...: AM16o75Gw9Yd0dnLqkaHc1iw/8SmWyFKdBRLp8g+1Bng3jf8j6UQ+iTV5eR1xYBoCYA/0VhcKIV4p3du5cG7mqpUCuXldUeL
   ...: S15QDfsXiL3aA5Zx8ymkXqdbPUDgcdVyIDxzNXDsXCJLKQqyeKFlYxBbSEJs14v9f+X/xRTx67AlXsIddMeS1LSNvUY4qS2q
   ...: Sy4GiP5FzcXROKYf8uXWTcS7DRNGusRJ13d7UPkGSO9gFWqVafBGSyeVehUp7q42ckbPMpBlMsv8GQ7TGIsx+eATBhNQNcc9
   ...: JORwziVLs5Mg/EtYeXbxRnyri/9ylnIA+GvlyO8B8UVmYdPcmb7KU/k61Pb6pMig2YL75g7tnUkshKB399/aiJec5ZvbwGLa
   ...: 46oIAQ8qP+XoD7la+mRY/sfwyMTGOy3KqquAL5e4tb"
# 导入AES包
In [3]: from Crypto.Cipher import AES
# 导入base64包
In [4]: import base64
# 赋值密钥
In [5]: key  =  "kPH+bIxk5D2deZiIxcaaaA=="
# 赋值IV
In [6]: IV = b' ' * 16
# 设置加密器，参数为密钥，CBC加密模式和IV
In [7]: encryptor = AES.new(base64.b64decode(key.encode()), AES.MODE_CBC, IV)
# 解密，cookie用base64解码后用加密器AES解密
In [8]: p_text = encryptor.decrypt(base64.b64decode(c_text.encode()))
# 查看解密结果，可以看到这里已经有了org.apache.shiro的序列化内容
In [11]: p_text
Out[11]: b'N\x88\xf1\x06q\xc3\x81\xc12OW\rR\x94\x83o\xac\xed\x00\x05sr\x002org.apache.shiro.subject.SimplePrincipalCollection\xa8\x7fX%\xc6\xa3\x08J\x03\x00\x01L\x00\x0frealmPrincipalst\x00\x0fLjava/util/Map;xpsr\x00\x17java.util.LinkedHashMap4\xc0N\\\x10l\xc0\xfb\x02\x00\x01Z\x00\x0baccessOrderxr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01t\x00\x08iniRealmsr\x00\x17java.util.LinkedHashSet\xd8l\xd7Z\x95\xdd*\x1e\x02\x00\x00xr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x10?@\x00\x00\x00\x00\x00\x01t\x00\x04rootxx\x00w\x01\x01q\x00~\x00\x05x\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
# 查看16进制的解密结果，可以看到16，17个字节就是序列化的0xac,0xed
In [14]: for num, p in enumerate(p_text):
    ...:     print(num, hex(p))
    ...:
0 0x4e
1 0x88
2 0xf1
3 0x6
4 0x71
5 0xc3
6 0x81
7 0xc1
8 0x32
9 0x4f
10 0x57
11 0xd
12 0x52
13 0x94
14 0x83
15 0x6f
16 0xac
17 0xed
18 0x0
19 0x5
20 0x73
```

我们可以看到16，17个字节就是反序列化的头部`0xac 0xed`，也就是说，第16个字节开始就是Java的序列化对象

#### CBC解密中的IV
我们上面说16个字节开始是Java的序列化对象，那么前16个字节是什么用的呢

我们看一下CBC解密的模式

![2-1](https://milkfr.github.io/assets/images/posts/2020-02-08-analysis-shiro-padding-oracle-1/2-1.png)

从上图可以看出，CBC解密的模式，从第二块开始就无关IV，只和块的密文有关，而我们有密文，有密钥，没有IV，所以我们可以确定16个字节之后的解密结果都是正确的，而前16字节是无用的弃子，因为可能是解密错误的

所以我们上面的16个字节后的结果是正确的，因为无关IV，而我们有密钥，所以是正确的

之所以是16个字节，是因为用的AES-128-CBC算法，128位就是16个字节

#### Shiro的Cookie的RememberMe的加解密流程分析
从上面的过程中我们可以看到，当我们获得Cookie以后，我们可以通过以下流程获取原本的Java对象 

```
base64decode(cookie)->c_text  # base64解码cookie变成密文
AES.decrpyt(c_text)-> serialize(Java Object)  # AES解密密文成为序列化后的Java对象
deserialize(serialize(Java Object)) -> Java Object  # 序列化后的Java对象反序列化成Java对象
```

说明加密的流程是

```
serialize(Java Object) -> serialize(Java Object)  # Java对象序列化 
AES.encode(serialize(Java Object)) -> c_text  # 序列化的Java对象被AES加密成密文
base64encode(c_text) -> cookie  # base64密文作为cookie
```

我们可以看一下源码佐证，上面我们学习Shiro中说到`CookieRememberMeManager`设置RememberMe的Cookie，我们在这个类中没有找到加密，在它继承的`AbstractRememberMeManager`中找到了

```
public abstract class AbstractRememberMeManager implements RememberMeManager {
    // 省略
    private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
    // 省略

    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        PrincipalCollection principals = null;
        try {
            byte[] bytes = this.getRememberedSerializedIdentity(subjectContext);
            if (bytes != null && bytes.length > 0) {
                principals = this.convertBytesToPrincipals(bytes, subjectContext);
            }
        } catch (RuntimeException var4) {
            principals = this.onRememberedPrincipalFailure(var4, subjectContext);
        }
        return principals;
    }

    protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        if (this.getCipherService() != null) {
            bytes = this.decrypt(bytes);
        }
        return this.deserialize(bytes);
    }

    protected PrincipalCollection deserialize(byte[] serializedIdentity) {
        return (PrincipalCollection)this.getSerializer().deserialize(serializedIdentity);
    }

    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {
        byte[] bytes = this.convertPrincipalsToBytes(accountPrincipals);
        this.rememberSerializedIdentity(subject, bytes);
    }

    protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
        byte[] bytes = this.serialize(principals);
        if (this.getCipherService() != null) {
            bytes = this.encrypt(bytes);
        }
        return bytes;
    }

    protected byte[] serialize(PrincipalCollection principals) {
        return this.getSerializer().serialize(principals);
    }

    // 省略

    protected byte[] encrypt(byte[] serialized) {
        byte[] value = serialized;
        CipherService cipherService = this.getCipherService();
        if (cipherService != null) {
            ByteSource byteSource = cipherService.encrypt(serialized, this.getEncryptionCipherKey());
            value = byteSource.getBytes();
        }

        return value;
    }

    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted;
        CipherService cipherService = this.getCipherService();
        if (cipherService != null) {
            ByteSource byteSource = cipherService.decrypt(encrypted, this.getDecryptionCipherKey());
            serialized = byteSource.getBytes();
        }

        return serialized;
    }

}
```

几个重要的方法都复制出来了

首先我们可以看到硬编码的密钥`private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");`，也是漏洞产生的原因之一

然后我们看到`getRememberedPrincipals->convertBytesToPrincipals->deserialize`的反序列化的过程，`rememberIdentity->convertPrincipalsToBytes->serialize`，有序列化就有反序列化漏洞，这是漏洞产生的原因之二

最后我们看到加解密的过程，跟进可以看全部的算法

#### 总结
漏洞成因之一：Shiro的AES的默认密钥固定编码在代码中，程序员替换过则无问题，否则满足条件

漏洞成因之二：Shiro的RememberMe的Cookie是序列化的Java对象，有序列化就有反序列化漏洞

攻击者能否控制序列化对象的加密是这个漏洞关键所在

### 0x03 下篇的基础
#### AES-128-CBC
AES就不说了，我也说不清楚

128就是128位，16个字节

CBC是CBC模式，将明文密文分块加解密，如下图

![3-1](https://milkfr.github.io/assets/images/posts/2020-02-08-analysis-shiro-padding-oracle-1/3-1.png)

![3-2](https://milkfr.github.io/assets/images/posts/2020-02-08-analysis-shiro-padding-oracle-1/3-2.png)

#### padding的问题
如果在GitHub上找Shiro-550的攻击PoC代码，会发现这么一行

```
BS = AES.block_size
pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
message = pad(payload)
```

简单解释一下就是

`AES.block_size`就是128，也就是16字节

pad的lambda函数是将`payload+(payload%16)*char(16-payload%16)`，也即是16字节为1块，payload分成多块之后，差n就填充n个n

![3-2](https://milkfr.github.io/assets/images/posts/2020-02-08-analysis-shiro-padding-oracle-1/3-2.png)

如上图，差一个就填充一个1，差2个就填充2个2，差4个填充4个4，差8个填充8个8

上面两小节提到的内容和我们之前讲的Shiro-550漏洞是我们下一篇的基础，也是Padding Oracle攻击的基础，和[hash长度扩展攻击](https://zh.wikipedia.org/zh-hans/%E9%95%BF%E5%BA%A6%E6%89%A9%E5%B1%95%E6%94%BB%E5%87%BB)有异曲同工之妙
