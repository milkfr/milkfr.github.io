---
title: Burp Suite插件编写editor-tab-codec
description: 编解码（加解密）结果在Message Editor Tab中显示的插件
categories:
 - Burp Suite
tags:
 - Burp Suite
 - 渗透工具
---

### 0x00 功能介绍
编解码（加解密）结果在Message Editor Tab中显示的插件

* 需要知道编解码（加解密）算法
* 在Proxy模块中查看解码（解密）信息
* 在Repeater中修改Payload值可以直接编码（加密）信息

![1](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-editor-tab-codec/1.png)

如图，Repeater页面就有一个Message Editor Tab，原本有Row、Params等Tab，插件为它新建了一个叫做Codec的Tab，点进去后就可以看到Codec的Tab对请求的参数进行分类显示，并对password参数用Base64解码显示到Decode上

### 0x01 编写需要
了解Burp `IMessageEditorTab`接口，了解一定的`JTable`等Java图形界面编写，需要知道参数的编解码（加解密）算法

### 0x02 详细使用
#### 编写编解码（加解密）函数
我的插件封装了一个抽象类，继承这个抽象并实现`encode`和`decode`方法作为加解密函数

```
package burp;

abstract class CodecMethod {

    public abstract String encode(String text);

    public abstract String decode(String text);
}
```

实现举例
```
package burp;

import java.util.Base64;

public class ExampleCodecMethod extends CodecMethod {

    @Override
    public String encode(String text) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(text.getBytes());
    }

    @Override
    public String decode(String text) {
        Base64.Decoder decoder = Base64.getDecoder();
        return new String(decoder.decode(text));
    }
}
```

#### 注册编解码（加解密）方法
在`CodecMap.java`中注册自己写的编解码（加解密）方法

需要确定参数类型和参数名字和继承抽象类`CodecMethod`的类，如下`register`函数中的`BODY`，`password`，`new ExampleCodecMethod()`是传入参数

```
CodecMap() {
    emptyMethod = new EmptyCodecMethod();
    registeredCodecMothods = new HashMap<String[], CodecMethod>();        register("BODY", "password", new ExampleCodecMethod());
}
```

#### 限定范围
在`CodecMap.java`中补完`filter`方法，限定请求的Scope
```
public boolean filter(String protocol, String host, int port) {
    // return host.equals("127.0.0.1");
    return true;
}
```

#### 搭建靶机
[vuln-web](https://github.com/milkfr/burp-extenders/tree/master/vuln-web)上有我自己搭的靶机，这里使用vuln-codec页面

请求包中的password参数经过了Base64编码

#### 使用
在Burp Suite中加载插件之后

找到任意的MessageEditorTab，打开Codec的Tab，即可找到对参数进行解码后的结果，在Repeater等可以对MessageEditorTab中的包信息进行修改的Tab中，还可以修改解码后的信息，Codec会自动更改编码信息并修改包

普通情况下显示解码后的信息，图片中的password

![2](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-editor-tab-codec/2.png)

修改Decode列的参数信息

![3](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-editor-tab-codec/3.png)

插件会自动对信息进行编码并修改包

![3](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-editor-tab-codec/4.png)