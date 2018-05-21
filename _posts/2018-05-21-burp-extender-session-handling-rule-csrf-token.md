---
title: Burp Suite插件编写session-handling-rule-csrf-token
description: 绕过CSRF Token等session-handling-rule插件
categories:
 - Burp Suite
tags:
 - Burp Suite
---

### 0x00 功能介绍
绕过CSRF Token

在Burp发送请求前先请求一次页面中带有CSRF Token的接口，解析其中的CSRF Token，替换掉包中已经过期的信息，从而绕过CSRF Token的限制，提高扫描效果因CSRF Token造成的准确率下降

一般CSRF Token是中间件，因此可以从一个页面解析的Token可以在其他页面使用，当然也需要根据实际情况修改解析策略

### 0x01 编写需要
了解Burp `ISessionHandlingAction`接口

### 0x02 详细使用
#### 编写CSRF Token的解析函数
重写`ISessionHandlingAction`接口的`public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems)`方法

`macroItesms`是发包前请求的页面列表，一般最后一个为我们需要的页面

```
public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
	if (macroItems == null) return;
	// in general, there is only one
	final byte[] finalResponse = macroItems[macroItems.length - 1].getResponse();

	if (finalResponse == null) return;

	String session = null;
	String csrfToken = null;
	IResponseInfo responseInfo = helpers.analyzeResponse(finalResponse);

	// get session info
	final List<String> headers = responseInfo.getHeaders();
	for (String header : headers) {
		if (header.startsWith("Set-Cookie")) {
			String pattern = "session=(.*?);";
			Pattern p = Pattern.compile(pattern);
			Matcher m = p.matcher(header);
			if (m.find()) {
				stderr.println("Found session: " + m.group(1));
				session = m.group(1);
			}
		}
	}

	if (session == null) return;

	int responseBodyOffset = helpers.analyzeResponse(finalResponse).getBodyOffset();
	String responseBody = new String(Arrays.copyOfRange(finalResponse, responseBodyOffset, finalResponse.length));
	String pattern = "<input name=\"csrf_token\" value=\"([a-zA-Z0-9]{40}\\.[a-zA-Z0-9=]{16}\\.[a-zA-Z0-9-_]{40})\" type=\"hidden\"/>";
	Pattern p = Pattern.compile(pattern);
	Matcher m = p.matcher(responseBody);
	if (m.find()) {
		stderr.println("Found csrf_token: " + m.group(1));
		csrfToken = m.group(1);
	}

	if (csrfToken == null) return;

	byte[] request = currentRequest.getRequest();

	List<IParameter> parameters = helpers.analyzeRequest(request).getParameters();
	for (IParameter parameter : parameters) {
		if (parameter.getType() == IParameter.PARAM_BODY && parameter.getName().equals(CSRF_TOKEN_KEY)) {
			request = helpers.updateParameter(request, helpers.buildParameter(CSRF_TOKEN_KEY, csrfToken, IParameter.PARAM_BODY));
		} else if (parameter.getType() == IParameter.PARAM_COOKIE && parameter.getName().equals(SESSION_KEY) ) {
			request = helpers.updateParameter(request, helpers.buildParameter(SESSION_KEY, session, IParameter.PARAM_COOKIE));
		}
	}
	currentRequest.setRequest(request);
}
```

代码从`macroItems`获取可以获得CSRF Token的页面，并从中用正则提取出CSRF Token，生成新的返回包

#### 搭建靶机
[vuln-web](https://github.com/milkfr/burp-extenders/tree/master/vuln-web)上有我自己搭的靶机，这里使用vuln-token页面

![1](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-csrf-token/1.png)

Repeater请求在正常情况下会被403 forbidden

![2](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-csrf-token/2.png)

#### rule设定
在Burp Suite中加载插件之后，在Project Options的Session选项中添加Session Handling Rules策略

选定作用域

![3](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-csrf-token/3.png)

添加Rule Action为Run a macro

![4](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-csrf-token/4.png)

给Macro items添加一个返回值中带有CSRF Token的请求，勾选使用自定义的Burp extension action handler

![5](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-csrf-token/5.png)

都点击确定后再次在Repeater重发刚才的Post包，会发现CSRF Token的值自动发生了改变，并且返回包不再被403 forbidden，而是一个正常的请求包

![6](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-session-handling-rule-csrf-token/6.png)