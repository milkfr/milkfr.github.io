---
title: Spring框架的IoC和AOP
description: 作为一个手艺人，只有if-else这样的代码能感到让人安心，Java框架里的各种XML配置实在让我觉得无语，因为完全看不清实现是怎么样的，和平常写代码差距实在太大，就一直没学，要克服克服，学学原理
categories:
 - Java
tags:
 - Java
---

学习安全的，学一些语言的框架，其实主要是为了理解这些框架产生的漏洞原理，很多情况下，我们通过打PoC，定位到出问题的代码，或者比对修复前后的代码，定位问题，虽然也可以说出个好歹来，但是对漏洞利用到的接口或者功能不熟悉，心理就会觉得有些落差，好像缺了点什么，Spring的插件出现过一些漏洞，所以了解一下Spring这个框架也是需要的

然后，和开发说明漏洞的危害或者排查问题的时候，直接说哪里哪里代码写成了什么样所以才有漏洞，他们不一定理解，所以多看看自己接口的开发们使用的技术，对自己是很有好处的

当然，不一定要清楚每个细节，但是让自己有个大概的意思，知道是语言的什么特性实现了什么功能，觉得自己胸有成竹了，还是很有必要的

这篇文章就讲讲对Spring基础的IoC和AOP的理解，因为Spring这些Java框架中的配置实在太恶心人了，只能照着别人的配置配，成功了也不知道这些配置到底做了什么，总让人心慌

### 0x00 看看历史，为什么出现Spring的IoC和AOP
#### IoC的历史
没用过Spring的话，先看一下我写的上一篇Spring环境搭建的文章，看一个小例子，有一点理解印像

做Java开发的时候，开发们总是会分很多层次，比如domain、service、controller、dao等

当要在controller中使用dao的对象的时候，一开始的一般的代码是这么写

```
public class UserController {
    public boolean register(User user) {
        UserDao userDao = new UserDao();
        return userDao.register(user);
    }
    public user login(String username, String password) {
        UserDao userDao = new UserDao();
        return userDao.login(username, password);
    }
}
```

这里我们可以看到，`UserDao userDao = new UserDao();`在每个方法中都需要出现

这样子有两个问题，新建实例就需要回收实例，对GC回收增加的压力，一个是controller和UserDao耦合

但是我们几乎可以马上想到使用单例或者工厂方法来减少CG回收的压力和结偶Dao的创建

```
public class UserDao {
    private static class SingletonHolder {
        private static final UserDaoSingleton instance = new UserDaoSingleton();
    }
    private UserDaoSingleton {
    }
    public static final UserDaoSingleton getInstance() {
        return SingletonHolder.instance;
    }
}

或者

public class UserController {
    private UserDao userDao = DaoFactory.getInstance().createDao("userDao"), UserDao.class);
    public boolean register(User user) {
        return userDao.register(user);
    }
    public user login(String username, String password) {
        return userDao.login(username, password);
    }
}
```

单例模式放在Dao中的话，耦合比较高，而且每个都写单例很麻烦，所以用工厂方法，那不通层次要实现不同的工厂方法，也很麻烦

后来大家就觉得，可不可以像数据库连接池一样有一个对象的连接池，这个就是IoC的容器，也是很多Java框架会设计的一个Container，然后程序员就可以将需要自己维护的一大堆bean交给Spring管理

其实Struts2里也有IoC的内容，但是没有Spring热

所以，只要考虑IoC实现的容器，怎么放对象、怎么管理对象、怎么获取对象、对象生命周期这些

关于IoC的实现，我们接下来的章节说明，这里，其实我们知道IoC最后实现的也只是上面这些代码，只是使得写代码的人简便了，程序性能优化了

#### AOP的历史
在以前我写Struts2的学习文章的时候，说到Struts2里面也用到了AOP

我们在写一个MVC的Controller的时候，主要有以下4个部分

* 控制层负责请求数据的接收
* 控制层负责业务逻辑的处理
* 控制层负责响应数据的收集
* 控制层负责响应流程的控制

实际上，除了对业务逻辑处理这一块需要程序员自己完成意外，Struts2通过AOP实现了其他三个部分，方便思考

Spring也是一样的原理

```
public class UserService {
    public User getById(String userId) {
        log("开始时候的记录");
        // 我们的逻辑代码
        log("结束时候的记录");
        return null;
    }
    public void add(User user) {
        log("开始时候的记录");
        // 我们的逻辑代码
        log("结束时候的记录");
    }
}
```

比如上面的代码中，`log`这个函数出现的地方有很多重复性的代码是可以抽取出来的，在我常用的语言Python中，肯定是用装饰器来实现，在Java中，可能使用的是动态代理模式，也就是AOP的基础

然后AOP的实现我们还是放到下面的章节中说明

### 0x01 IoC和AOP的一些基础
#### 首先要理解依赖倒置原则
> 因为IoC确实不够开门见山，因此业界曾进行了广泛的讨论，最终软件界的泰斗级人物Martin Fowler提出DI（Dependency Injection，依赖注入）的概念来代替IoC，即让调用类对某一接口实现类的依赖关系由第三方（容器或协作类）注入，以移除调用类对某一接口实现类的依赖。"依赖注入"这个名词显然比"控制反转"直接明了、易于理解。

引用自《精通Spring 4.x 企业应用开发实战》

要了解反转控制（Inversion of Control），首先要了解设计模式中一个重要思想：依赖倒置原则（Dependency Inversion Principle）

依赖倒置原则定义：高层模块不应该依赖底层模块，二者都应该依赖其抽象

抽象不应该依赖细节，细节应该依赖抽象

针对接口编程，不要针对实现编程

优点：可以减少类间的耦合性，提高系统稳定性，提高代码可读性和可维护性，可降低修改程序所造成的风险

先设置一个命题，一个学生需要学习一些课程，应用层代码如下
```
// 应用层代码
public class Test {
    public static void main(String[] args) {
        Student student = newStudent();
        student.studyJavaCourse();
    }
}

// Student类
public class Student {
    public void study JavaCourse() {
        System.out.println("Java");
    }
}
```

如果学生要学习更多的课程，比如`studyPythonCourse`，我们就需要在Student类中加一个方法，需要学多少课程，就需要加多少方法

我们用倒置依赖的思路进行改进

```
// 应用类
public class Test {
    public static void main(String[] args) {
        Studentstudent = newStudent();
        student.study(newJavaCourse());
        student.study(newPythonCourse());
    }
}
// 课程接口类
public interface ICourse{
    void studyCouse();
}
// 课程接口实现类
public class JavaCourse implements ICourse {
    @Override
    public void studyCouse(){
        System.out.println("Java");
    }
}
// student类
public class Student {
    public void study(ICourseiCourse) {
        iCourse.studyCouse();
    }
}
```

这样修改后，Test是应用层，变更时必须修改，但是只要Student不修改，那么底层的课程类只需要扩展，而不需要修改，Student类和Course类都依赖抽象的ICourse接口

以抽象为基础搭建的架构要比以细节为基础搭建的架构稳定得多，因为细节多变，面向接口编程

在一条更长的链中

比如电脑依赖CPU，CPU依赖矿物这样三层

普通情况下，我们要定义电脑、CPU、矿物三个类

```
class PC {
    private CPU cpu;
    PC () { this.cpu = new CPU(); }
}
class CPU {
    private Mineral mineral; 
    CPU () { this.mineral = new Mineral(); }
}
class Mineral {
    private String from;
    Mineral () { this.from = "earth"; }
}
```

PC构造时在内部生成了CPU和Mineral

此时如果Mineral的构造函数变化了

```
class Mineral {
    private String from;
    Mineral (String from) { this.from = from; }
}
```

那么CPU和PC的构造函数都需要加上参数from，指定矿物来源

我们用依赖倒置的思想修改

```
class PC {
    private CPU cpu;
    PC (CPU cpu) { this.cpu = cpu; }
}
class CPU {
    private Mineral mineral; 
    CPU (Mineral mineral) { this.mineral = new mineral; }
}
class Mineral {
    private String from;
    Mineral (String from) { this.from = from; }
}
```

此时，初始化时填入的参数就可以替换，不必在意底层的实现

```
Mineral mineral = new Mineral("earth");
CPU cpu = new CPU(mineral);
PC pc = new PC(cpu);
```

这就是倒置依赖的好处，同时上面这个PC的例子也是构造方法注入的IoC实现

其他的实现方式有

通过setter方法接入

```
class PC {
    private CPU cpu;
    PC () {}
    public void setCpu(CPU cpu) { this.cpu = cpu; }
    public CPU getCpu(CPU cpu) { return this.cpu; }
}
```

通过接口注入，也就是我们一开始举例的Student的例子，Student和Course通过ICourse接口和studyCourse方法实现IoC

#### IoC实现方式比较
* 接口注入：相对于其他两种方式，这种方式比较死板和繁琐，如果需要注入依赖对象，被注入对象就必须声明和实现另外的接口，是不倡导使用的方式，因为它强制被注入对象实现不必要的接口，带有侵入性
* 构造方法注入：优点是，对象构造完成之后，就进入就绪状态，可以马上使用，缺点是依赖对象较多的时候，构造方法列表很长，而通过反射构造对象的时候，对相同类型的参数的处理会比较困难，维护和使用上也比较麻烦，而且Java中，构造方法无法被继承，无法设置默认值，对于非必须的依赖处理，可能需要引入多个构造方法，而参数数量的变动可能造成维护上的不便
* setter方法注入：因为方法可以命名，所以setter方法注入在描述性上要比构造方法注入好一些，另外，setter方法可以被继承，允许设置默认值，有良好IDE支持，缺点是对象无法在构造完成后马上使用

#### IoC的附加值
IoC是一种可以帮助我们解耦各个业务对象间依赖关系的对象绑定方式

和依赖倒置原则一样，可以减少类间的耦合性，提高系统稳定性，提高代码可读性和可维护性，可降低修改程序所造成的风险

#### 了解一些Java注解
看一下我写的这个[Java的注解](https://milkfr.github.io/java/2019/09/11/java-annotation/)

#### AOP和Java动态代理
看一下我写的这个[Java代理模式](https://milkfr.github.io/java/2019/09/22/java-proxy/)

再看一篇知乎的文章，用动态代理模式了Spring的事务管理，[浅谈JDK动态代理（下）](https://zhuanlan.zhihu.com/p/63126398)

### 0x02 Spring框架中的IoC和AOP
说实话我讲不清楚，本来想用自己的语言组织一下自己理解，但是太难了，其中最大的原因当然是就算看了一部分书和源码分析，也只是顺着流程知道了一遍，它为什么这么设计，这里为什么这样写，其实太模糊了，所以自己写一些分析也只是把别人的抄一遍，不如直接贴出我觉得写的很好的文章，在谈谈理解

首先需要在理解注解的情况下看这一篇[Spring基础2：放弃XML，走向注解](https://zhuanlan.zhihu.com/p/72668451)

主要是要理解Spring的Bean如何和容器绑定，也就是如何IoC，要理解

* 3种编程风格：XML、注解、JavaConfig
* 2种注入方式：setter方法、构造方法
* 4种装配模式：byType、byName、constructor、no

像我一样学安全的话，我觉得之后忘记也没关系，留个映像，看完的时候留下一个恍然大悟的感觉，以后想到了能翻出来就可以

那理解了上边这篇，我们就可以回顾IoC的目的是解耦各个业务对象间依赖关系的对象绑定方式，也就是通过一个容器，同一维护所有bean的关系和生命周期等

以上的这些方式，是为了将Bean交给容器，去掉容器管理Bean这层关系，我们把Bean当成代码中的内容也没有关系，没有Spring用容器维护Bean不影响我们理解

一般来说，容器是个map，map维护了所有的bean，然而实际上，Spring的map是一个单例池

然而当我们知道了容器只是管理Bean，也就是IoC以后，并没有解决我们对Spring框架不清楚的感觉，因为我们真正不清楚的地方，是我们不知道忘Spring里注册的Bean以后，很多操作就解放了，比如数据库的事务管理，但是仅仅注册一个Bean，并不能解放这些，那到底Spring做了什么解放了这些呢

我们一开始说，感觉Spring令人心慌的原因，是只知道照着配置抄后，就会帮我们完成很多事情，但是单单把Bean交给Spring管理生命周期似乎只是管理对象创建销毁和调用，并没有影响到我们不知道的Spring到底做了什么事情

然后我们需要走入第二阶段，看一看这篇文章[Spring基础(1)：两个概念](https://zhuanlan.zhihu.com/p/70642885)和这篇文章[浅谈JDK动态代理（下）](https://zhuanlan.zhihu.com/p/63126398)

第一篇文章给我们介绍了一个观点，我们像Spring中注册的Bean，不一定是我们自己写的Bean，在很多情况下，这个Bean经过了Spring的加工，而加工的方式就是AOP

第二篇文章给我们介绍了如果用AOP实现一个事务管理的代码的简化，也就是如何让我们写事务的时候只关心处理的逻辑，而不必关系数据库连接关闭，事务开启关闭

这两篇文章告诉我们，Spring解析一个Bean后，并不是直接将它存到map中，而是根据注解的不同，用AOP进行了一系列的加工，然后返回一个功能增强的代理对象的Bean

知晓了这些以后，我们可以大致得出一些结论

* 和我们普通写一个Web APP不同的是，Spring用IoC帮助我们管理了对象的生命周期，防止创建销毁对象的开销，同时为我们解耦对象关系
* 但是Spring的IoC不仅仅是将对象放入一个单例池的map，它还做了很多额外的操作，根据使用者选择的注解的不同，它会增强注册的Bean，通过AOP的方式给使用者一个增强的功能的代理类
* 至于如果我们对某个注解和它增强的功能不理解的话，觉得模糊的话，就只能看对应的代码，看AOP增强了哪些功能

到此，其实我对Spring学习后的理解就完了，剩下的只能在使用或者接下来学习中学习了

如果对上面几篇文章看的不够过瘾，我再推荐几篇

[Spring基础(3)：复习](https://zhuanlan.zhihu.com/p/74807335)

[Spring源码解析(1)：Bean容器](https://zhuanlan.zhihu.com/p/74832770)

[SpringBoot启动原理解析](https://zhuanlan.zhihu.com/p/99205565)：这篇讲SpringBoot的注解成分和启动原理，从Spring过渡到SpringBoot很有必要