---
title: SQL Injection
description: SQL注入漏洞简介与防御方式
categories:
 - 通用漏洞
tags:
 - 通用漏洞
---

### 0x00 概述
大学时代老师上课经常说:
> 你们毕业了去挖漏洞是没有意思的，在参数后面加个引号，就算拖个数据，也一点意思都没有，你们现在学的数学啊，编程啊都用不到

> 密码学是有意思的，上两届有个学生成绩很好，很愿意学习，保送的时候让我推荐老师，我问他想干什么，他说想研究密码，我就跟他说，算了吧，换个方向吧，不是你能研究的，智商不够的

> 所以到我的实验室里来研究推荐系统、图像处理都是不错的

写SQL注入之前，我想写什么好呢，告诉大家参数后面加个引号来引申出注入的概念，把数据段当代码段执行吗？

后来想想渗透提有SQL注入问题的单，没有人回来咨询这个漏洞是什么意思，想必有点经验的开发都了解了吧，知道原理也会修复

再后来想想即使大家基本都是知道，也还是会写出SQL注入的漏洞代码，于是这个漏洞又有了可说的地方

本文从知乎上的一个问题出发，引出SQL注入的成因引出SQL注入的修复方式，之后再对SQL注入详细介绍

### 0x01 漏洞简介
#### 知乎上的问题
知乎上有一个[为什么参数化SQL查询可以防止SQL注入?](https://www.zhihu.com/question/52869762)的问题，如果你了解SQL注入就能看明白，如果你不了解，可以从下一节看起，再回过头来看知乎的回答

看一看下面的回答，大部分是在代码逻辑中如何调用参数化查询的函数来防止SQL，或者说解释SQL注入的原因，相必你和我一样看了会有不清不楚的感觉，说起来也很简单，我们需要的是`PreparedStatement`对外提供函数内部实现代码，讲清楚它的实现，兴许我们就明白了这个问题，然而其实，了解了它的实现，可能我们还需要知道数据库的实现才能明白，因为参数化查询是数据库提供的能力，少部分回答讲到了这个，但是疑问没解决是因为这些回答都没有展示数据库的代码

#### 什么是SQL注入（SQL Injection）
不考虑SQL注入漏洞防御的业务逻辑
```
String username = req.getParameter("username");
String password = req.getParameter("password");
String url = "jdbc:mysql://127.0.0.1:3308/wwy221?useUnicode=true&characterEncoding=utf8";
Connection conn = DriverManager.getConnection(url, conname, passworddb);
String sql = "select * from user where username='" + username + "' and password='" + password + "'";
ResultSet rs = stement.executeQuery(sql);
```

正常情况下，假如用户提交`username=goodman&password=mypasswrod`，上面代码中执行的SQL语句就是`select * from user where username = 'goodman' and password = 'mypassword'`

非正常情况下，用户提交`username=badman&password=idonotknow' or '1'='1`，上面代码中执行的SQL语句就是`select * from user where username=badman and password = 'idonotknow' or '1'='1'`，此时无论提交什么密码，只要`'1'=='1'`，条件语句就会成立

我们说，非正常情况下的SQL语义发生了改变，本应该作为数据的`password`参数成为了影响SQL语句执行的代码，改变SQL执行代码的判断逻辑，把数据段作为代码段执行，也是所有注入类型的漏洞的根本原因

此时我们要注意，`password`是作为SQL语句的数据，改变的代码逻辑是数据库的执行代码，而不是我们自己写的应用程序的代码，这一点很重要

#### SQL Injection原理
上面说到注入类型漏洞的原因是把数据段当成代码段执行，那么为什么会把数据段当作代码段执行呢，我们为什么把漏洞叫做SQL注入，而不是Java注入或者语言注入

C语言的`printf("%s", data)`，即使你输入的`data="abc"); system("shutdown /s");`，C语言也不会把它拼接成`printf("%s" "abc"); system("shutdown /s");`，C语言不会这样做的原因我是说不清楚的，但这是语言编译器解释器的功劳

字符串拼接是应用程序做的，而SQL语句执行是数据库做的，SQL语句和我们`bash`命令行一样，只是忠实执行用户输入的字符串，程序作为用户向数据库发送`select * from user where 1=1`，只要语法正确，数据库一定执行

这也是把数据段当成代码段执行的根本原因，跨程序用SQL协议通信，应用程序返回给数据库的是Opeation和Object混用的整条执行语句，应用程序侧没有区分，而数据库忠实地执行了应用程序给出的代码

至此，SQL注入的原理就是
* 应用程序过分信任用户，没有检查用户输入，直接拼接SQL语句
* 应用程序没有区分SQL的Operation和Object，导致恶意SQL拼接成功，混和数据段和代码段
* 数据库过分信任用户（应用程序），直接执行用户（应用程序）输入，将数据段当作代码段执行

#### SQL注入最好防御手段（参数化查询）
参数化查询避免SQL注入的代码
```
String username = req.getParameter("username");
String password = req.getParameter("password");
String url = "jdbc:mysql://127.0.0.1:3308/aaaaa?useUnicode=true&characterEncoding=utf8";
Connection conn = DriverManager.getConnection(url, conname, passworddb);
String sql = "select * from user where username= ? and password= ?";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, username );
pstmt.setString( 2, password );
try
{
	ResultSet results = pstmt.execute( );
}
```

首先我们要说明的是，参数化查询是数据库提供的能力，而不是应用代码，不是语言和库的能力，而我们在应用中写的参数化查询代码只是调用了这种能力，`PreparedStatement`是对这个调用过程的封装

而要说明参数化查询是怎么防御SQL注入的，笔者并没有这种说明能力，因为对数据库也没有研究，不能show数据库的code，但是参考上面知乎的回答，我们可以大致得出预编译应该和语言编译后执行类似，就像C语言`printf("%s", data)`后传入`data="abc"); system("shutdown /s");`也只会输出`data="abc"); system("shutdown /s");`，而不会执行`printf("%s" "abc"); system("shutdown /s");`

然后我们要说为什么参数化查询是最好的防御手段，我们应用的代码不可以吗，防御的WAF一类的安全措施不可以吗

我们上面说到SQL注入的原理有3点，可以简化为
* 应用程序没有检查用户输入
* 应用程序没有正确处理SQL语句代码段和数据段
* 数据库没有检查应用程序发出的执行命令

要避免SQL注入，就要避免上面的问题

没有参数化查询的情况下，应用程序只能传回Operation和Object混用的SQL整条语句，第二点原理无法避免，第一点原理的检查用户输入，就需要强大的检查规则，如果确实足够强大似乎可以，但是业务逻辑复杂，有时候我们需要类似`'"\<>`一类的特殊符号，需要放过检查，因此需要对第三点做文章

我们上面说到SQL注入改变的是数据库的执行代码，而不是应用逻辑的，更不是应用逻辑外部为保护应用而写的应用了，在直接执行的应用（也就是数据库）中进行防御是最好的，不管在应用层上对输入参数做多么有效的防护都不如在数据库层，也就是最终执行者直接防御要好，同时，参数化查询需要在业务逻辑上调用，业务逻辑的调用也能帮助开发者区分传入到数据库的SQL语句的数据段和代码段

因此，防御SQL，最推荐用参数化查询

回到上面知乎的问题，笔者觉得回答这个问题需要说明
* SQL注入的原理究竟是什么
* 参数化查询是数据库实现的，为什么要在数据库实现
* 参数化查询在数据库中是什么实现的，实现的代码逻辑大致是怎么样的

能深入研究的话读者可以去回答一下

### 0x02 威胁场景
我们说数据往往是最重要的，我们将数据存在数据库中，用SQL操作数据，因此SQL注入漏洞造成的危害也往往是最大的，毕竟和数据相关

因此，在威胁场景这里，我们说说我见过的业务常写出SQL注入的原因和可以利用漏洞做些什么（也就是危害）

#### 写出SQL注入的原因
原因往往有两个

一是缺乏对SQL注入的了解，不知者无畏，就随意拼接，能执行就好

一般这种情况下，整站所有接口都有SQL注入问题，所以修复起来也很麻烦，往往不能让全站修改为参数化查询，只能做过滤限制

二是了解SQL注入，但为了方便

比如使用ORM，ORM本身是使用参数化查询的方式的，但是存在一些情况，需要执行的SQL语句很复杂，ORM调用者对ORM语法方法并不熟悉，但是对SQL语法本身很熟练，为了赶进度或者为了方便，某些SQL语句就自己写自己拼接，不使用ORM，此时ORM养成的习惯忘记了使用参数化查询

还有一种情况是`ORDER BY`和`GROUP BY`的情况

```
SELECT * FROM table_A ORDER BY field_A
SELECT * FROM table_A ORDER BY `field_A`
SELECT * FROM table_A ORDER BY 1
```

上面的语句在预处理过程中

* 如果使用数字类型的列索引号，是可以被预处理保护的，但实际应用场景很少
* 如果参数被识别为字符串类型，经过预处理后会被单引号包裹导致ORDER BY条件失效

出现这类情况时开发可能会选择拼接字符串而不是使用预处理，但没有白名单过滤传入的内容

#### SQL注入的危害
我们经常能听到的就是拖库

SQL注入的能造成的危害实际上是产生漏洞的SQL语句可以做到的，它取决于两个方面

* 能拼接成什么样的SQL语句，这又和应用SQL拼接的写法和对用户参数的过滤转义强度有关
* 应用程序作为用户使用数据库的权限

在拥有足够权限的情况下，SQL注入能做到
* 操作数据（读、写）
* 操作服务器文件（读、写）

具体这里就不深入说明，可能在下面的深入攻防一节的靶场讲解中了解

### 0x03 修复方式
#### 参数化查询
上面的SQL注入介绍中我们已经说了这种方式，这是目前最好的防御方式

典型的应用层代码
```
String username = req.getParameter("username");
String password = req.getParameter("password");
String url = "jdbc:mysql://127.0.0.1:3308/aaaaa?useUnicode=true&characterEncoding=utf8";
Connection conn = DriverManager.getConnection(url, conname, passworddb);
String sql = "select * from user where username= ? and password= ?";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, username );
pstmt.setString( 2, password );
try
{
	ResultSet results = pstmt.execute( );
}
```

现在的ORM都是默认使用参数化查询的

但是仍然要注意上面威胁场景一节讲到的明知SQL注入的原因，还会写出SQL注入漏洞的情况

对于参数化查询的实现有想了解，可以参考[这篇文章](https://xz.aliyun.com/t/2075)，从SQL的协议出发写得比较详细

#### 参数白名单过滤
应用层对用户输入过滤也是一种办法，比较推荐白名单，因为黑名单被绕过的可能性更大

#### 数据库权限最小化
安全里的最小权限原则，连接数据库用户是功能需求的最小权限，启动数据库的用户不是root，而是较小权限的系统用户，可以降低出现漏洞后的损失以及这是一种良好的习惯

### 0x04 深入攻防
无需讲解，靠手熟，熟了之后靠漏洞情报，推荐一个SQL注入靶场

[sqli-labs](https://github.com/Audi-1/sqli-labs)

对这个靶场的讲解

[讲解笔记](https://legacy.gitbook.com/book/wangyihang/sqli-labs/details)

[讲解笔记](https://xz.aliyun.com/t/385)

[讲解笔记](https://xz.aliyun.com/t/376)

[讲解笔记](https://xz.aliyun.com/t/370)

### 0x05 总结
本文从SQL注入的原因和参数化查询可以防御的原因出发讲解SQL注入漏洞

和开篇笔者老师说的那样，笔者也觉得其实SQL注入的成因也是很弱智了

> 你们毕业了去挖漏洞是没有意思的，在参数后面加个引号，就算拖个数据，也一点意思都没有，你们现在学的数学啊，编程啊都用不到

所以希望开发们在了解以后都不要写出SQL注入漏洞

### 0x06 参考资料
《白帽子讲Web安全》

[OWSAP SQL Injection](https://www.owasp.org/index.php/SQL_Injection)