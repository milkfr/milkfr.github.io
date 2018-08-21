---
title: Burp Suite插件编写session-handling-rule-sign
description: 改包时重签名的session-handling-rule插件
categories:
 - Burp Suite
tags:
 - Burp Suite
 - 渗透工具
---

### 0x00 功能介绍
一些安全性好的页面会在前端对用户输入的一些参数进行签名，提高一定攻击的难度，使用Burp工具改包后签名没有变化，后台验证签名出错会认为无效包，需要在改包后对参数重签名

* 改包后重签名
* 需要知道签名的算法
* 在对参数进行修改之后，重新签名，避免签名问题导致的改包失效

### 0x01 编写需要
了解Burp `ISessionHandlingAction`接口，需要知道页面使用的签名算法

### 0x02 详细使用
#### 编写签名函数
重写`ISessionHandlingAction`接口的`public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems)`方法，对参数进行重签名

`macroItesms`是发包前请求的页面列表，一般最后一个为我们需要的页面

```
public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
    byte[] request = currentRequest.getRequest();

    List<IParameter> parameters = helpers.analyzeRequest(request).getParameters();

    String username = null;
    String password = null;
    for (IParameter parameter : parameters) {
        if (parameter.getType() == IParameter.PARAM_BODY && parameter.getName().equals("username")) {
            username = parameter.getValue();
        } else if (parameter.getType() == IParameter.PARAM_BODY && parameter.getName().equals("password")) {
            password = parameter.getValue();
        }
    }

    if (username == null || password == null) return;
    String sign_hash = null;
    try {
        sign_hash = sign(username + "." + password, "secret key");
    } catch (Exception e) {
        stderr.println(e);
        return;
    }

    currentRequest.setRequest(helpers.updateParameter(request, helpers.buildParameter("sign_hash", sign_hash, IParameter.PARAM_BODY)));
}
```

在知晓签名算法的情况下对代码进行修改，改变参数签名方式

#### 搭建靶机
[vuln-web](https://github.com/milkfr/burp-extenders/tree/master/vuln-web)上有我自己搭的靶机，这里使用vuln-sign页面

![1](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-sign/1.png)

Repeater请求在修改username从原来的123到1234的情况下会被403 forbidden

#### rule设定
在Burp Suite中加载插件之后，在Project Options的Session选项中添加Session Handling Rules策略

选定作用域

![2](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-sign/2.png)

添加Rule Action为Invoke the extension handler，然后选择相应的插件

![3](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-sign/2.png)

![4](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-sign/2.png)

都点击确定后再次在Repeater重发刚才的Post包，会发现sign的值自动发生了改变，并且返回包不再被403 forbidden，而是一个正常的请求包

![5](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-sign/5.png)
