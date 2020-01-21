---
title: Java代理模式
description: 设计模式其实我都看过，但是写代码用到不多，理解不深刻，也没背，重点学习一下Java代理模式，是因为Java动态代理在很多框架中用到，不学实在看不懂
categories:
 - Java
tags:
 - Java
---

### 0x00 一个需求
比如在Action中要添加日志，记录输入和输出

原来

```
public class Action {
    public void execute(HttpServletRequest request, HttpServletResponse response) {
        // 业务代码
    }
}
```

直接修改的方式

```
public class Action {
    public void execute(HttpServletRequest request, HttpServletResponse response) {
        System.out.println(request);
        // 业务代码
        System.out.println(response);
    }
}
```

我们可以预见，如果一个项目有100个action，就要加两百行代码，而且每次新增接口都要加，如果有一天要把`System.out.println`改成`log`，就要把这几百行重写一变

### 0x01 静态代理
#### 先看一下实现
```
public class ActionProxy {
    private Action target;
    public ActionProxy(Action action) {
        this.target = target;
    }
    public void execute(HttpServletRequest request, HttpServletResponse response) {
        System.out.println(request);
        target.execute(request, response);
        System.out.println(response);
    }
}
```

这样是不是很简洁明了，将原来需要执行的类做为参数传入，执行我们需要添加的操作，还是和Python的装饰器类似

#### 存在的不足
* 如果Action的默认方法就几百个，那我们的Proxy就要重写这几百个方法，同时，重写方法中打印也存在代码重复
* 如果不是Action类，而是其他类型，我们又要重新完成一个Proxy

### 0x02 动态代理
#### 先来看一下实现
```
interface Interface { public void foo(); }

class A implements Interface {
    public void foo { System.out.println("Method a of class A!"); }
}

class Consumer {
    public static void consume(Interface i) {
        i.foo();
    }
}

class DynamicProxyHandler implements InvocationHandler {
    private Object proxied;
    public DynamicProxyHandler(Object proxied) {
        this.proxied = proxied;
    }
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        try {
            // do before
            return method.invoke(proxied, args);
            // do after
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }
}

public class Test {
    public static void main(String[] args) {
        A a = new A();
        Interface proxy = (Interface) Proxy.newProxyInstance(Interface.class.getClassLoader(), new Class<?>[]{Interface.class}, new DynamicProxyHandler(a));
        Consumer.consume(proxy);
    }
}
```

我们看看这种情况下比上面静态代理都改进了哪里

不用对同一个接口的所有方式都进行重写了，接口方法作为参数传入，然后接口类型也作为参数传入，实现相同都功能就不用为一个接口实现一个代理

#### 一些原理
实际上使用上对动态代理的使用也就是这样了，但是我在学习的时候看了很多资料，试图解释动态代理实现上究竟做了什么事情，这些内容其实比较难懂，需要多看几遍，也不一定全弄懂

[浅谈JDK动态代理（中）](https://zhuanlan.zhihu.com/p/62660956)

[Java JDK动态代理Proxy类的原理是什么？](https://www.zhihu.com/question/49337471/answer/115462314)

我们看JDK实现动态使用的主要方法`newProxyInstance`

```
static Object newProxyInstance(ClassLoader loader, Class<?>[] interfaces,InvocationHandler h)
```

它有三个参数

* ClassLoader loader：指定当前对象使用类加载器，获取加载器的方法是固定的
* Class<?> interfaces：目标对象实现的接口的类型，使用泛型方式确认类型
* InvocationHandler h：事件处理，执行目标对象的方法时，会触发事件处理器的方法，会把当前执行目标对象的方法作为参数传入

根据上面文章的意思，前两个参数用来动态生成类名、方法名、继承关系的一个空壳

```
class $ProxyN implements Interface {
    public void foo() {
    }
}
```

也就上面的A类变成了上面`$ProxyN`这类，有一样的方法

然后当我们调用上面的`$ProxyN`类的时候，会调用实现了InvocationHandler接口的DynamicProxyHandler里的`invoke`方法

大致是这样一个实现

看一下newProxyInstance方法源码

```
/*
 * Choose a name for the proxy class to generate.
 */
long num = nextUniqueNumber.getAndIncrement();
String proxyName = proxyPkg + proxyClassNamePrefix + num;

/*
 * Generate the specified proxy class.
 */
byte[] proxyClassFile = ProxyGenerator.generateProxyClass(
    proxyName, interfaces, accessFlags);
try {
    return defineClass0(loader, proxyName,
                        proxyClassFile, 0, proxyClassFile.length);
} catch (ClassFormatError e) {
    /*
     * A ClassFormatError here means that (barring bugs in the
     * proxy class generation code) there was some other
     * invalid aspect of the arguments supplied to the proxy
     * class creation (such as virtual machine limitations
     * exceeded).
     */
    throw new IllegalArgumentException(e.toString());
}
```

上面是一段文章中说的`newProxyInstance`中重要的实现代码

`$ProxyN`是动态生成的代理类的名称，N代表N次生成动态代理

`ProxyGenerator.generateProxyClass`方法生成了类加载器需要的字节码，根据类名和事件的接口Class对象，相当与凭空编译好一个`.class`文件

通过上面这个方法生成的字节码加上加载器和类型被交到`defineClass0`里，由它生成代理类的Class对象
