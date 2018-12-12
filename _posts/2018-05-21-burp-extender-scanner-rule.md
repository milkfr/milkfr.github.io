---
title: Burp Suite插件编写scanner-rule
description: 自定义Burp Suite的Scanner规则
categories:
 - 渗透工具
tags:
 - Burp Suite
 - 渗透工具
---

### 0x00 功能介绍
自定义Burp Suite的Scanner规则

* 可以定制Payload
* 可以定制Payload的插入点
* 可以定制Payload的编码修改
* 可以定制扫描结果的报告信息

Burp Suite本身带有Scanner，有部分漏洞的扫描规则，但是某些时候还是需要对一些行为检测进行定制

### 0x01 编写需要
了解Burp `IScannerInsertionPointProvider`，`IScannerCheck`，`IScanIssue`接口

### 0x02 详细使用
#### 编写Scan方法
实现举例
```
public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
    String[] payloads = new String[]{"121", "122", "123"};
    for (String payload : payloads) {
        byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
        byte[] checkResponse = checkRequestResponse.getResponse();
        if (helpers.analyzeResponse(checkResponse).getStatusCode() == 200) {
            List<IScanIssue> issues = new ArrayList<>(1);
            List<int []> marker = new ArrayList<int []>();
            int start = helpers.indexOf(checkResponse, payload.getBytes(), true, 0, checkResponse.length);
            int end = start + payload.length();
            marker.add(new int[] {start, end});
            issues.add(new ScanIssue(baseRequestResponse, new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, null, marker)}));
            return issues;
        }

    }
    return null;
}
```

这里是暴力破解密码的Payload，字典只有121，122，123三个，只是Demo

或者实现`doPassiveScan`方法

实现一个继承`IScanIssue`接口的类，实现其中对事件描述的方法
```
class ScanIssue implements IScanIssue {
    ......
}
```

实现`IScannerInsertionPointProvider`接口和`IScannerInsertionPoint`添加扫描规则的注入点

```
/**
 * implement IScannerInsertionPointProvider
 */
@Override
public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
    IParameter parameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "password");
    if (parameter == null) {
        return null;
    }

    List<IScannerInsertionPoint> scannerInsertionPoints = new ArrayList<IScannerInsertionPoint>();
    scannerInsertionPoints.add(new ScannerInsertionPoint(baseRequestResponse.getRequest(), parameter));
    return scannerInsertionPoints;
}
    
@Override
public byte[] buildRequest(byte[] payload) {
    String input = helpers.base64Encode(payload);
    byte[] request = helpers.updateParameter(baseRequest, helpers.buildParameter(parameter.getName(), input, parameter.getType()));
    return request;
}
```

这里将带有password参数的参数作为注入点，将password参数的值替换为Base64编码后的Payload

#### 搭建靶机
[vuln-web](https://github.com/milkfr/burp-extenders/tree/master/vuln-web)上有我自己搭的靶机，这里使用vuln-codec页面

请求包中的password参数经过了Base64编码

#### 使用
普通情况下爆破password，修改password值为123没有结果，用Scanner扫描也无法暴力破解

![1](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-scanner-rule/1.png)

加载插件后在Scanner的Options里选择Extension generated issue

![2](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-scanner-rule/2.png)

再进行扫描得到暴力破解的结果

![3](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-scanner-rule/3.png)