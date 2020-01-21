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

### 0x01 IoC
> 因为IoC确实不够开门见山，因此业界曾进行了广泛的讨论，最终软件界的泰斗级人物Martin Fowler提出DI（Dependency Injection，依赖注入）的概念来代替IoC，即让调用类对某一接口实现类的依赖关系由第三方（容器或协作类）注入，以移除调用类对某一接口实现类的依赖。"依赖注入"这个名词显然比"控制反转"直接明了、易于理解。

引用自《精通Spring 4.x 企业应用开发实战》

#### 首先要理解依赖倒置原则
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

#### IoC的附加值
IoC是一种可以帮助我们解耦各个业务对象间依赖关系的对象绑定方式

和依赖倒置原则一样，可以减少类间的耦合性，提高系统稳定性，提高代码可读性和可维护性，可降低修改程序所造成的风险

#### IoC实现方式比较
* 接口注入：相对于其他两种方式，这种方式比较死板和繁琐，如果需要注入依赖对象，被注入对象就必须声明和实现另外的接口，是不倡导使用的方式，因为它强制被注入对象实现不必要的接口，带有侵入性
* 构造方法注入：优点是，对象构造完成之后，就进入就绪状态，可以马上使用，缺点是依赖对象较多的时候，构造方法列表很长，而通过反射构造对象的时候，对相同类型的参数的处理会比较困难，维护和使用上也比较麻烦，而且Java中，构造方法无法被继承，无法设置默认值，对于非必须的依赖处理，可能需要引入多个构造方法，而参数数量的变动可能造成维护上的不便
* setter方法注入：因为方法可以命名，所以setter方法注入在描述性上要比构造方法注入好一些，另外，setter方法可以被继承，允许设置默认值，有良好IDE支持，缺点是对象无法在构造完成后马上使用

详细的方法可以网上搜，网上有很多，也不会写错，我估计我记录了也记不住

#### 注解实现IoC



### IoC Service Provider
虽然业务对象可以通过IoC方式声明相应的依赖，但是最终仍然需要通过某种角色或者服务将这些相互依赖的对象绑定到一起，IoC Service Provider对应的IoC场景就属于这一角色

学到这里的时候，想到以前学Struts2的XWork的容器也是IoC Service Provider，而且是通过注解的方式实现的IoC

#### IoC Service Provider的职责
* 业务对象的构建管理：在IoC场景中，业务对象无需关系所依赖的对象如何构建如何取得，所以就要由IoC Service Provider来做，它把需要的对象的构建逻辑从客户端对象那里剥离出来，以免这部分逻辑污染业务对象的实现
* 业务对象的依赖绑定：IoC Service Provider通过结合之前构建和管理的所有业务对象，以及各个业务对象间可以识别的依赖关系，将这些对象所依赖的对象注入绑定，从而保证每个业务对象在使用的时候，可以处于就绪状态

#### IoC Service Provider如何管理对象间依赖关系
* 直接编码方式：通过代码注册，通过创建对象，然后register和bind创建依赖关系
* XML等配置文件方式：读取文件解析，之后和直接编码方式一样，但是用算法解析实现更方便自动化和修改
* 元数据方式：直接在类中指明元数据信息来标注各个对象之间的依赖关系，然后用注解@inject将这些对象组装后，交给客户端使用（以前在Struts2的XWork容器分析的文章中介绍过这个）

### Spring的IoC容器
Spring的IoC容器是一个提供IoC支持的轻量级容器，除了基本的IoC支持，它作为轻量级容器还提供来IoC之外的支持，这里仅讨论IoC相关支持及衍生的部分特性

Spring提供了两种容器类型

* BeanFactory：基础类型的IoC容器，提供完整的IoC服务支持，默认采用延迟初始化策略（lazy-load），只有当客户端对象需要访问容器中某个受管对象的时候，才对该受管对象进行初始化以及依赖注入操作，容器启动快，所需资源有限，对于资源有限但功能要求不严格的场景是比较合适的选择
* ApplicationContext：ApplicationContext在BeanFactory的基础上构建，是相对高级的容器实现，多提供一些特性，它所管理的对象，在该容器启动后，默认全部初始化并绑定，启动慢，在系统资源充足，并且要求更多功能的场景中是比较合适的选择
* BeanFactory是Spring框架的基础设施，面向Spring本身，一般成为IoC容器，ApplicationContext面向Spring框架的开发者，称为应用上下文，也称为Spring容器，几乎所有应用场合都可以直接使用ApplicationContext而非底层的BeanFactory

#### BeanFactory


#### ApplicationContext

### 0x02 AOP