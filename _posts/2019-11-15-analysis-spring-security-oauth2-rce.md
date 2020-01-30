---
title: Spring Security OAuth2 两个远程命令执行漏洞
description: 学习了一下Spring框架以后，分析一下Spring的一些历史漏洞，找一些网上有环境的比较严重的漏洞分析，这篇分析Spring Security OAuth2的两个远程命令执行漏洞
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 历史漏洞
刚学完Spring框架，趁热学习一下它的历史漏洞，从vulhub、vulapps和网上找到一些有直接环境的漏洞分析一下

最难的是找到漏洞环境然后复现，Spring不像Struts2一样分析环境那么多，可以一个个试，基本会成功

虽然vulhub有一些环境，但是看Dockerfile是编译好的jar，有些不好debug调试

一些博客写了漏洞作者提供的环境，但是大多都已经年久失修，站点都没有了

所以只能能进行调试的调试，不能的找文章看明白

大部分都是Spring的组件使用SpEL表达式导致的问题，也是在框架页面模版或者参数中注入表达式语言，和Struts2对OGNL表达式不同，大部分组件都没有执行沙箱的限制，所以基本不需要绕过，基本上直接放入SpEL表达式就可以远程命令执行

现成功实验了两个Spring Security OAuth2漏洞

### 0x01 CVE-2018-1260环境
因为CVE-2018-1260的日期更近，而且分析CVE-2016-4977的文章中的环境所在漏洞发现者的站点已经访问不到了，vulhub里的环境要docker启动，比较麻烦弄成debug环境

所以我最开始打算通过[这篇文章](https://xz.aliyun.com/t/2330)说的环境对CVE-2018-1260进行分析

我们首先看这个漏洞，因为这个漏洞可以找到debug环境进行分析，比较方便，而且这个漏洞其实和CVE-2016-4977是差不多一样的，所以看了这个漏洞，看CVE-2016-4977就差不多

[漏洞环境地址](https://github.com/wanghongfei/spring-security-oauth2-example)，这个应该是普通java开发者写的example，按README配置好maven和数据库表

我自己mac电脑装的mysql8，然后漏洞的`spring-security-auth2`的版本可能不对，所以需要自己指定，如下添加一下依赖版本

```
<dependency>
    <groupId>org.springframework.security.oauth</groupId>
    <artifactId>spring-security-oauth2</artifactId>
    <version>2.0.10.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
    <version>2.2.4.RELEASE</version>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>8.0.18</version>
</dependency>
```

PoC为`/oauth/authorize?client_id=client&response_type=code&redirect_uri=http://www.github.com/&scope=%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22open%20/System/Applications/Calculator.app%22%29%7D`

执行的SpEL表达式为`${T(java.lang.Runtime).getRuntime().exec("open /System/Applications/Calculator.app")}`

然后我修改PoC执行的的SpEL表达式为`2333-1`，就可以直接证明

![1-1](https://milkfr.github.io/assets/images/posts/2019-11-15-analysis-spring-security-oauth2-rce/1-1.png)

### 0x02 CVE-2018-1260分析
其实我们不需要知道OAuth2协议的过程，虽然一些文章中分析，但是不是协议实现出现了问题，所以至少和OAuth2的关系不大，我们首先找到PoC对应的URL`/oauth/authorize`，对应的处理逻辑根据URL Mapping

`org.springframework.security.oauth2.provider.endpoint.AuthenticationEndpoint`

```
@RequestMapping({"/oauth/authorize"})
public ModelAndView authorize(Map<String, Object> model, @RequestParam Map<String, String> parameters, SessionStatus sessionStatus, Principal principal) {
    AuthorizationRequest authorizationRequest = this.getOAuth2RequestFactory().createAuthorizationRequest(parameters);
    // 省略
                ClientDetails client = this.getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());
    // 省略
                    this.oauth2RequestValidator.validateScope(authorizationRequest, client);
    // 省略
                    return this.getUserApprovalPageResponse(model, authorizationRequest, (Authentication)principal);
    // 省略
}
```

我这里省略了大部分的逻辑，因为我们只需要知道漏洞出现在scope参数，这个对URL处理的函数获取Request，然后有一个验证scope的函数验证了，之后就返回Response这三步就可以了，知道验证参数的来源就可以

然后单步进去我们看验证函数

![2-1](https://milkfr.github.io/assets/images/posts/2019-11-15-analysis-spring-security-oauth2-rce/2-1.png)

这里是比较懵的，clientScopes是个LinkedHashSet，size为0，但是为空的检查项没有检查出来，很奇怪，可能是没有重载`isEmpty`方法，这个`clientScope`值检查错误，所以跳过了验证

这个clientScopes是配置项scopes的值，没有配置为空，否则会进行检查

总之最后没有检查，就开始Response的构造

```
private ModelAndView getUserApprovalPageResponse(Map<String, Object> model, AuthorizationRequest authorizationRequest, Authentication principal) {
    this.logger.debug("Loading user approval page: " + this.userApprovalPage);
    model.putAll(this.userApprovalHandler.getUserApprovalRequest(authorizationRequest, principal));
    return new ModelAndView(this.userApprovalPage, model);
}
```

这个Response的构造就是生成了一个`ModelAndView`，参数`this.userApprovalPage="forward:/oauth/confirm_access"`也就是跳转到`/oauth/confirm_access`

然后我们就找到`/oauth/access`对应的函数

`org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint`

```
@RequestMapping({"/oauth/confirm_access"})
public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request) throws Exception {
    String template = this.createTemplate(model, request);
    if (request.getAttribute("_csrf") != null) {
        model.put("_csrf", request.getAttribute("_csrf"));
    }

    return new ModelAndView(new SpelView(template), model);
}
```

最后是进入到SpelView中

```
class SpelView implements View {
    public SpelView(String template) {
        this.template = template;
        this.prefix = (new RandomValueStringGenerator()).generate() + "{";
        this.context.addPropertyAccessor(new MapAccessor());
        this.resolver = new PlaceholderResolver() {
            public String resolvePlaceholder(String name) {
                Expression expression = SpelView.this.parser.parseExpression(name);
                Object value = expression.getValue(SpelView.this.context);
                return value == null ? null : value.toString();
            }
        };
    }
    public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response) throws Exception {
        Map<String, Object> map = new HashMap(model);
        String path = ServletUriComponentsBuilder.fromContextPath(request).build().getPath();
        map.put("path", path == null ? "" : path);
        this.context.setRootObject(map);
        String maskedTemplate = this.template.replace("${", this.prefix);
        PropertyPlaceholderHelper helper = new PropertyPlaceholderHelper(this.prefix, "}");
        String result = helper.replacePlaceholders(maskedTemplate, this.resolver);
        result = result.replace(this.prefix, "${");
        response.setContentType(this.getContentType());
        response.getWriter().append(result);
    }
}
```

重要的是这两个函数，一个是构造函数，一个是对template渲染函数

我们先看下渲染过程的变化

最开始的template

![2-2](https://milkfr.github.io/assets/images/posts/2019-11-15-analysis-spring-security-oauth2-rce/2-2.png)

然后是中间模版

![2-3](https://milkfr.github.io/assets/images/posts/2019-11-15-analysis-spring-security-oauth2-rce/2-3.png)

最后是渲染结果

![2-4](https://milkfr.github.io/assets/images/posts/2019-11-15-analysis-spring-security-oauth2-rce/2-4.png)

就是说对任何`${}`格式的SpEL表达式进行了执行，所以造成了漏洞

所以漏洞有两个问题

一个是对scope的验证出现错误，并在之后调用SpEl表达式

二是SpEL表达是没有想Struts2之后的OGNL一样沙箱处理

当然漏洞利用条件比较苛刻

* 需要scopes没有配置白名单
* 使用了默认的Approval Endpoint，一般会对自己网站适配
* 角色是授权服务器（例如@EnableAuthorizationServer）

### 0x03 CVE-2016-4977漏洞
这个漏洞其实和上一个漏洞的原因是差不多的，而且都是相同的地方出现问题，可以看[这篇分析文章](https://paper.seebug.org/70/)

上个漏洞生成Response的是`org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint`

这个漏洞生成Response的是`org.springframework.security.oauth2.provider.endpoint.WhitelabelErrorEndpoint`

所以和上面一样，漏洞的原因也是两个

一个是对`redirect_url`等参数出错的时候，原来的值进入了`errorSummary`参数中，没有进行验证，并在之后使用了SpEl表达式

二是SpEL表达是没有想Struts2之后的OGNL一样沙箱处理

上面分析文章中说的

> 可以看到在第一次执行表达式之前程序将`$`替换成了由`RandomValueStringGenerator().generate()`生成的随机字符串，也就是`${errorSummary} -> random{errorSummary}`，但是这个替换不是递归的，所以${2334-1}并没有变。
  
> 然后创建了一个`helper`使程序取`random{}`中的内容作为表达式，这样就使得`errorSummary`被作为表达式执行了，而`${2334-1}`因为不符合`random{}`这个形式所以没有被当作表达式，从而也就没有办法被执行了。
  
> 不过这个`Patch`有一个缺点：`RandomValueStringGenerator`生成的字符串虽然内容随机，但长度固定为6，所以存在暴力破解的可能性。

感觉这个文章中的说法经过我debug后是会递归调用的，把CVE-2018-1260的PoC改成`${${}}`的形式，还是可以触发

![3-1](https://milkfr.github.io/assets/images/posts/2019-11-15-analysis-spring-security-oauth2-rce/3-1.png)

所以按[这篇文章](https://xz.aliyun.com/t/2330)中说的比较对，之后的版本去掉SpelView换用其他实现

### 0x02 Spring Data Rest远程代码执行漏洞（CVE-2017-8046）