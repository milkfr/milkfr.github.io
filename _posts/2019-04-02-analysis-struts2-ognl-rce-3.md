---
title: struts2基于OGNL的RCE漏洞分析3——看修复历史和一些思考
description: 承接上两篇，先通过上两篇的分析说说数据流转，然后看struts2的修复历史，在谈自己的一些思考
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 Web框架中的数据流转
上两篇文章中我常常讲到数据流转，这个是从《Struts2 技术内幕——深入解析Struts2架构设计与实现原理》这本书中学来的词汇，我以前关于Struts2框架的分析文章也有很多是基于这本书的

书中对数据流转大概是这么说的，网络中传输的是二进制或者字符类型的数据，是弱类型的，而Java世界是一个强类型的，而且可以自定义类型，为了方便这种类型转换，就使用了表达式引擎，也就是OGNL表达式引擎

其实SQL注入也是一样，HTTP协议的传送的二进制或者字符类型，语言是强类型的，然后SQL语言是弱类型的，经过这样的类型转换，就形成了注入漏洞

所以Struts2的OGNL的RCE其实也都是一种另类的注入漏洞

Struts2框架设计上有一个目的，就是将XWork和容器的Servlet分开，也就是重新封装HttpServletRequest和HttpServletResponse，将传入的参数直接传到Action的属性中去

这样设计很灵活，可以将HTTP参数转变成Java自定义的对象，也留下的隐患，HTTP数据和Java世界中就像SQL注入一样增加了一个OGNL表达式，所以注入就能够这样出现，而OGNL比SQL注入更厉害的是很容易代码执行

其实我之前两篇文章强行将漏洞产生划分成HTTP请求到Struts2到Request到数据流转和Struts2到Response到HTTP返回这两个区域是不对的，比如s2-007就要intercept和jsp的生成配合，在请求和返回中都遇到

但是不可否认，是因为在这两个过程的数据转换的操作和适配中出现的错误，才导致漏洞的产生，其他Struts2的漏洞也是如此，而往往对入参解析就是intercept，也就是Struts2将HTTP请求转换成struts2中的对象，对返回标签重定向等解析就是struts2中的Result，将struts2中的对象转换成HTTP响应，也有两者配合的情况

过于灵活的数据流转就是漏洞产生主要因素，我想这在所有的Web框架中都有参考意义

### 0x01 Struts2基于OGNL的RCE的修复历史
目前，Struts2框架已经有s2-001、s2-003、s2-005、s2-007、s2-008、s2-009、s2-012、s2-013、s2-015、s2-016、s2-019、s2-029、s2-032、s2-033、s2-037、s2-045、s2-046、s2-048、s2-052、s2-053、s2-057这些RCE漏洞，基本都和OGNL有关

注入点存在参数名、参数值、content-type、cookie、url等各种可以出现的地方

注入的语法又有`(ognl)(constant)=value&(constant)((ognl1)(ognl2))，%{ognl}，${ognl}`等

#### 一些事前要了解的注意点
可以先看这个了解[OGNL整体](https://milkfr.github.io/java/2019/02/03/java-struts2-3/)

主要是要先了解OGNL的三要素和一些表达式和几个重要的数据结构（_root，_values，ClassResolver，TypeConverter，MemberAccess）和它们在Struts2中的实现和扩展

然后注意struts-default.xml中存有黑名单的类和包和Struts2扩展MemberAccess用的SecurityMemberAccess里的allowStaticMethodAccess属性和其他方法

```
    <constant name="struts.excludedClasses"
              value="
                java.lang.Object,
                java.lang.Runtime,
                java.lang.System,
                java.lang.Class,
                java.lang.ClassLoader,
                java.lang.Shutdown,
                java.lang.ProcessBuilder,
                sun.misc.Unsafe,
                com.opensymphony.xwork2.ActionContext" />

    <!-- this must be valid regex, each '.' in package name must be escaped! -->
    <!-- it's more flexible but slower than simple string comparison -->
    <!-- constant name="struts.excludedPackageNamePatterns" value="^java\.lang\..*,^ognl.*,^(?!javax\.servlet\..+)(javax\..+)" / -->

    <!-- this is simpler version of the above used with string comparison -->
    <constant name="struts.excludedPackageNames"
              value="
                ognl.,
                java.io.,
                java.net.,
                java.nio.,
                javax.,
                freemarker.core.,
                freemarker.template.,
                freemarker.ext.jsp.,
                freemarker.ext.rhino.,
                sun.misc.,
                sun.reflect.,
                javassist.,
                org.apache.velocity.,
                org.objectweb.asm.,
                org.springframework.context.,
                com.opensymphony.xwork2.inject.,
                com.opensymphony.xwork2.ognl.,
                com.opensymphony.xwork2.security.,
                com.opensymphony.xwork2.util." />
```

#### 原始阶段
s2-001的PoC

`%{@java.lang.Runtime@getRuntime().exec("open /Applications/Calculator.app/")}`

可以看到这里PoC是可以直接调用java.lang.Runtime的，也就是说，这个时候，Struts2基本属于不设防的状态，只要可以执行OGNL，就可以代码执行

#### struts2-core2.0.9和XWork的2.0.4版本前
s2-003和s2-005开始PoC有了不同

其实看[s2-003官方公告](https://cwiki.apache.org/confluence/display/WW/S2-003)上，s2-003官方认为是allow OGNL statement execution，因为问题是`('\u0023' + 'session\'user\'')(unused)=0wn3d`，而s2-005是RCE

其实两者都可以RCE，但是公告确不同

从网上的PoC来看，003、005以后开始PoC往往都要分成两个部分

```
('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(a)(b)&('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(a)(b)&('\u0023_memberAccess.allowStaticMethodAccess\u003dfalse')(a)(b)&('\u0040java.lang.Runtime@getRuntime().exec(\'open\u0020/Applications/Notes.app/\')')(a)(b)`
```

类似上面分成两个部分

第一部分`\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(a)(b)&('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(a)(b)&('\u0023_memberAccess.allowStaticMethodAccess\u003dfalse')(a)(b)`

第二部分`('\u0040java.lang.Runtime@getRuntime().exec(\'open\u0020/Applications/Notes.app/\')')(a)(b)`

第二部分其实是原本的直接执行的PoC内容，就是需要执行的代码，第一部分约等于

```
#context['xwork.MethodAccessor.denyMethodExecution=false
#_memberAccess.excludeProperties=@java.util.Collections(@EMPTY_SET)
#_memberAccess.allowStaticMethodAccess=false
```

也就是说，这时候框架的OGNL的上下文环境里存在一些配置，从名字就可以看出是限制，包括denyMethodExecution（拒绝执行命令），excludeProperties（黑名单），allowStaticMethodAccess（不允许静态方法访问）

所以PoC要先去掉这些配置，才可以执行java.lang.Runtime，通过直接调用OGNL表达式，可以修改原来初始化时候的配置

我们从maven仓库中下载xwork的包，比对一下，这里没有很精确，比对了2.0.0和2.0.7，可以发现allowStaticMethodAccess这个限制是增加的

![1-1](https://milkfr.github.io/assets/images/posts/2019-04-02-analysis-struts2-ognl-rce-3/1-1.png)

![1-2](https://milkfr.github.io/assets/images/posts/2019-04-02-analysis-struts2-ognl-rce-3/1-2.png)

也就是说从某个版本开始，官方意识到OGNL执行代码的问题，增加了一个SecurityMemberAccess类，进行一些限制，不出意外是s2-001修复的sturts2的2.0.9版本，xwork2.0.4版本

```
public class SecurityMemberAccess extends DefaultMemberAccess {

    private boolean allowStaticMethodAccess;
    Set<Pattern> excludeProperties = Collections.emptySet();
    Set<Pattern> acceptProperties = Collections.emptySet();

    public SecurityMemberAccess(boolean method) {
        super(false);
        allowStaticMethodAccess = method;
    }
    // 省略其他
}
```

然而这个限制在s2-003和s2-005开始就被安全人员绕过了，而官方只是对问题产生的点进行修复，没有对SecurityMemberAccess进一步优化

#### struts2-core2.3.14.2和xwork-core2.3.14.2版本前
上面说到s2-003和s2-005之后只是修修补补，没有对SecurityMemberAccess优化

所以后面s2-007，s2-009，s2-012，s-013，s2-014，s2-015出现了一堆漏洞，基本上都可以用类似`${#_memberAccess["allowStaticMethodAccess"]=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())}`的方式，当然也存在特殊情况需要适配

![1-3](https://milkfr.github.io/assets/images/posts/2019-04-02-analysis-struts2-ognl-rce-3/1-3.png)

可以从上面看到，2.3.14.2版本后，将allowStaticMethodAccess设置成final后，就不能更改了，所以这些漏洞基本上升级到2.3.14.2就解决了

#### 黑名单的增加
再之后S2-016，S2-019，S2-029，S2-032，S2-033，S2-037...

```
#a=new java.lang.ProcessBuilder(new java.lang.String[]{"netstat","-an"}).start()

(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('xcalc'))

(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('xcalc'))
```

在上面将allowStaticMethodAccess置为final之后，不可以通过设置allowStaticMethodAccess来赋值

于是就出现了上面三种新的方法，

第一种是通过构造函数访问公共函数，比较好理解

第二种是覆盖`_memberAccess`，原本Struts2中的`_memberAccess`是xwork2扩展了MemberAccess，考虑了安全，加上allowStaticMethodAccess和黑名单，第二种PoC用SecurityMemberAccess和父类DefaultMemberAccess覆盖了`_memberAccess`中的内容，相当于初始化了_memberAccess

第三种是覆盖通过container（要理解java项目里常有的容器的概念）获取了OgnlUtil实例，清空黑名单，再覆盖`_memberAccess`

官方修复方式就是在struts-default.xml中增加的黑名单`java.lang.ProcessBuilder`，`ognl.MemberAccess`，`ognl.DefaultMemberAccess`，`com.opensymphony.xwork2.ognl`

#### 当前的版本
2.5.0以后增加了很多限制，除了黑名单增加（如最开始给的struts-default.xml中的黑名单）

比如OgnlUtil中setXWorkConverter、setExcludedPackageNames、setContainer等诸多函数从public方法变成protected方法了

比如直接删除了DefaultMemberAccess，SecurityMemberAccess直接继承了DefaultMemberAccess，直接转为实现MemberAccess接口

当然整个变化过程中肯定还有很多我没有发现的地方不能一一举例

### 0x02 思考，为什么修不好
上面我们从数据流转和struts2对OGNL对限制历史讲了修复历史，实际上每个漏洞，对具体产生漏洞的解析的地方也做了处理，这个没有讲

也就是说，struts2对RCE修复是缝缝补补，偶尔像前两篇解析s2-001和s2-007一样，对关键部位对具体逻辑加了一些限制，然后有些版本会大力推动OGNL解析的安全

实际上像Struts2这样的框架因为有很多用户，修复上不能大刀阔斧，会担心兼容的问题，很多为了保持灵活不敢变动吧

我们前面把Struts2的OGNL造成的RCE类比成SQL注入，因为都是数据流转造成的问题，想想struts2为什么不能想SQL注入一样修复

我们说使用`PreparedStatement`对SQL注入进行修复，实际上是修复了数据库对应用输入的信任，让数据库对输入对语句进行预编译，让应用传入参数而不是代码

而Struts2对OGNL对修复，不是修复OGNL表达式对应用输入对信任，让OGNL编译好要执行的语句，让应用只传入参数，而是仍然由应用去控制对OGNL的操作，只不过加强了限制条件

原因是struts2需要灵活以及它不是默认安全的，我想一般来说安全一定会限制灵活

但是比如现代的前端框架，都默认对XSS进行了转义，如果不需要，需要在模版中使用过滤器，类似`{ code | not_escape }`，一般开发者不了解XSS，实现功能遇到问题看框架文档，就会增加XSS的安全意识

但是struts2不是，它默认不会在使用OGNL时使用强限制，除非用户指定才开放限制，它最开始是默认完全开放了OGNL，慢慢增加限制，对于不了解OGNL安全的开发者，很可能中招

我们当然可以说是为了灵活，虽然我不知道struts2出现的时代是有多需要那么灵活的框架，但是将一个令我很意外的点

在Struts2的早期版本，实现一个action

```
public class LoginAction extends ActionSupport {
    private Integer age = null;
    private String name = null;
    private String email = null;

    public LoginAction() {
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public String execute() throws Exception {
        System.out.println(this.age);
        return !this.name.isEmpty() && !this.email.isEmpty() ? "success" : "error";
    }
}
```

配置好struts.xml

```
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE struts PUBLIC
        "-//Apache Software Foundation//DTD Struts Configuration 2.3//EN"
        "http://struts.apache.org/dtds/struts-2.3.dtd">

<struts>
    <package name="privilige" extends="struts-default">
        <action name="login" class="io.github.milkfr.LoginAction">
            <result name="success">/welcome.jsp</result>
            <result name="error">/index.jsp</result>
            <result name="input">/index.jsp</result>
        </action>
    </package>
</struts>
```

我们竟然可以通过访问`login!getName!action`访问从外部访问到getName方法，也就是URL Mapping也太灵活了，而且恐怕这个功能也不容易被人发现，估计没有几个开发会故意用

这和将方法public有关，也和URL Mapping的设计有关，总是感觉，其实没必要那么灵活，这些特性恐怕开发者也用不到

灵活的背后就是漏洞，而且又没有默认安全，不管对应用开发者还是框架开发者都没有一个警惕

然后就是对数据流转过程中限制不够，这些都是写框架和挖漏洞需要关注的点，再有就是修复上不断被绕过，就是被发现的漏洞驱动，没有防范于未然了，当然这也和安全研究员确实比较厉害有关

### 参考文档
https://xz.aliyun.com/t/4607

https://github.com/HatBoy/Struts2-Scan

https://bithack.io/forum/178

https://www.freebuf.com/vuls/168609.html