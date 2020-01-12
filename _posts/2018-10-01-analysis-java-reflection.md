---
title: 如何理解Java的反射 
description: 安全研究中，常常使用反射，可以绕过一些沙盒，所以要先理解Java的反射
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 什么是反射
```
public void execute(String className, String methodName) throws Exception {
    Class clazz = Class.forName(className);
    clazz.getMethod(methodName).invoke(clazz.newInstance());
}
```

首先理解反射的作用，最常用的就上面这段代码

* 根据类名创建实例（类型可以从配置文件读取，不用new，达到解耦）
* 用Method.invoke执行方法

我不是Java开发，现在还是不太理解JVM的，但是这张图现在差不多能看懂就好
 
![0-1](https://milkfr.github.io/assets/images/posts/2018-10-01-analysis-java-reflection/0-1.png)

`Object o = new Object();`

运行上面这行代码

* 通过javac把代码编译成.class文件
* JVM启动通过ClassLoader加载.class文件到JVM内存
* 这个时候类Object加载到方法区中，创建了Object类的Class对象到堆中，注意这个不是new出来的对象，而是类的类型对象，每个类只有一个class对象，作为方法区类的数据结构的接口
* JVM创建对象前，会检查类是否加载，寻找类对应的class对象，若加载好，就为对象分配内存，初始化，也就是new Object()

上面是正常创建实例的方法，如果服务器上突然遇到某个请求要用到某个类，没加载进JVM，就报错，要是我们需要动态加载一个类，因为我们启动程序前还不确定会不会用到，怕提前加载了占内存，就要用到反射

日常开发中理解反射的目的主要有两个

* 创建实例
* 反射调用方法

安全里常用来绕过沙盒，执行命令执行

### 0x01 反射API理解
反射常用的4个方法

* 获取类的方法(forName)
* 实例化类对象的方法(newInstance)
* 获取函数的方法(getMethod)
* 执行函数的方法(invoke)

以及绕过中常用的两个方法

* 获取构造函数(getConstructor)
* 获取声明的构造函数(getDeclaredConstructor)

#### 获取类
通常来讲我们有如下三种方式获取一个类，也就是`java.lang.Class`对象

* `A.class`，如果已经加载好了类，只是想获取`java.lang.Class`对象，就直接获取`class`属性就可以，这个方式不属于反射
* `Class.forName`，知道类名，可以用这个函数获取
* `obj.getClass()`，如果上下文存在某个类的实例，就一个通过这个方法获取

`forName`有两个函数重载

```
public static Class<?> forName(String className)
            throws ClassNotFoundException {
    Class<?> caller = Reflection.getCallerClass();
    return forName0(className, true, ClassLoader.getClassLoader(caller), caller);
}

public static Class<?> forName(String name, boolean initialize,
                               ClassLoader loader)
    throws ClassNotFoundException
{
    Class<?> caller = null;
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
        caller = Reflection.getCallerClass();
        if (sun.misc.VM.isSystemDomainLoader(loader)) {
            ClassLoader ccl = ClassLoader.getClassLoader(caller);
            if (!sun.misc.VM.isSystemDomainLoader(ccl)) {
                sm.checkPermission(
                    SecurityConstants.GET_CLASSLOADER_PERMISSION);
            }
        }
    }
    return forName0(name, initialize, loader, caller);
}
```

第二个重载方法中，第一个参数是类名、第二个表示是否初始化，第三个参数是ClassLoader

第一个和第三个比较常见，第二个是用来确定是否执行类初始化，也就是下面static代码块，在forName时执行

```
package io.github.milkfr;

public class Test2 {
    {
        System.out.println("1");
    }

    static {
        System.out.println("2");
    }

    public Test2() {
        System.out.println("3");
    }
}
```

可以通过`Class.forName("test$test2")`加载内部类

```
package io.github.milkfr;

public class Test {
    class Test2 {
    }
}

class Test3 {
}
```

用`javac Test.java`编译一下

```
Test$Test2.class
Test.class
Test.java
Test3.class
```

通过forName获取类之后，我们就可以继续用反射操作类

#### 获取构造函数
`class.newInstance`是调用这个类的无参构造函数，这个类没有重载，也就是说构造函数有参数就不能使用，同时，调用newInstance有个要求，就是类的构造函数不能是私有的

![1-1](https://milkfr.github.io/assets/images/posts/2018-10-01-analysis-java-reflection/1-1.png)

我们调用`java.lang.Runtime`就会报错，所以单例模式的类都不能直接获取实例，但是一般单例模式的类都提供获取对象的方式，比如`java.lang.Runtime.getRuntime`，如下就可以执行，不会报错

![1-2](https://milkfr.github.io/assets/images/posts/2018-10-01-analysis-java-reflection/1-2.png)

那么如果是一个类没有无参构造方法，也没有类似单例模式里的静态方法，如何实例化类对象

比如Java中另一种执行命令的`ProcessBuilder`，它没有无参构造方法和获取实例的静态方法，有两个构造函数

```
public ProcessBuilder(List<String> command) {
    if (command == null)
        throw new NullPointerException();
    this.command = command;
}

public ProcessBuilder(String... command) {
    this.command = new ArrayList<>(command.length);
    for (String arg : command)
        this.command.add(arg);
}
```

我们可以使用，如下两个方式实现反射执行 

![1-3](https://milkfr.github.io/assets/images/posts/2018-10-01-analysis-java-reflection/1-3.png)

![1-4](https://milkfr.github.io/assets/images/posts/2018-10-01-analysis-java-reflection/1-4.png)

通过`getConstructor`方法获取构造函数，可变长参数`string...`等于数组

如果一个方法的构造方式是私有方法，如何执行

![1-5](https://milkfr.github.io/assets/images/posts/2018-10-01-analysis-java-reflection/1-5.png)

`getDeclared`系列的方法获取当前类中"声明"的方法，包括私有的方法，但是不包括父类的，`getMethod`是获取公共方法，包括父类的

`setAccessible`是获得私有方法后，使用setAccessible方法修改作用域，否则仍然不能调用

#### 获取和执行方法
然后就是`getMethod`和`invoke`方法，这两个方法需要配合

因为方法存在重载，所以`getMethod`方法需要加上类型参数来区分

`invoke`的作用是执行方法，如果是普通方法，第一个参数是类实例，如果是静态方法，第一个参数是就是类，这里比较好理解，我们通过执行方法是

```
instance.method(arg1, arg2, ...)
class.method(arg1, arg2, ...)
```

在反射里就是

```
method.invoke(instance, arg1, arg2, ...)
method.invoke(class, arg1, args2, ...)
```
