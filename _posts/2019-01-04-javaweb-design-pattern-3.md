---
title: Java Web研习二：背一些设计模式
description: 结构型模式
categories:
 - Java Web
tags:
 - Java Web
---

### 外观
定义：又叫门面模式，提供了一个统一的接口，用来访问子系统中的一群接口

外观模式定义了一个高层接口，让子系统更容易使用

类型：结构型

适用场景：子系统越来越复杂，增加外观模式提供简单接口调用，构建多层系统结构，利用外观对象作为每层的入口，简化层间调用

优点：简化了调用过程，无须了解深入子系统，防止带来风险，减少系统依赖、松散耦合，更好的划分访问层次，符合迪米特原则

缺点：增加子系统、扩展子系统的行为容易引入风险，不符合开闭原则

### 装饰者
定义：在不改变原有对象的基础上，将功能附加到对象上

提供了比继承更有弹性的替代方案（扩展原有对象功能）

类型：结构型

适用场景：扩展一个类的功能或给一个类添加附加职责，动态给一个对象添加功能，这些功能可以再动态的撤销

优点：继承的有力补充，比继承灵活，不改变原有对象的情况下给一个对象扩展功能，通过使用不同装饰类以及这些装饰类的排列组合，可以实现不同效果，符合开闭原则

缺点：会出现更多的代码，更多的类，增加程序复杂性，动态装饰时，多层装饰时会更加复杂

举例：

```
public class Battercake {
    protected int cost() {
        return 8;
    }
}

public class BattercakeWithEgg extends Battercake {
    @Override
    public String cost() {
        return super.cost() + 1;
    }
}
```

如上，如果我们需要再加一个鸡蛋，就需要再继承一个类，用装饰器模式可以如下

```
public abstract class ABattercake {
    protected abstract int cost();
}

public class Battercate extends ABattercake {
    @Override
    protected int cost() {
        return 8;
    }
}

public class AbstractDecorator extends ABattercake{
    private ABattercake aBattercake;

    public AbstractDecorator(ABattercake aBattercake) {
        this.aBattercake = aBattercake;
    }
    
    @Override
    protected int cost() {
        return aBattercake.cost();
    }
}

public class EggDecorator extends AbstractDecorator{

    public EggDecorator(ABattercake aBattercake) {
        super(aBattercake);
    }

    @Override
    protected int cost() {
        return super.cost()+1;
    }
}
```

应用上，加鸡蛋就可以这样，最后嵌套调用cost

```
public class Test {
    public static void main(String[]args){
        ABattercake aBattercake;
        aBattercake = new Battercate();
        aBattercake = new EggDecorator(aBattercake);
        aBattercake = new EggDecorator(aBattercake);
    }
}
```

### 适配器模式
定义：将一个类的接口转换成客户期望的另一个接口

使原本接口不兼容的类可以一起工作

类型：结构型

适用场景：已经存在的类，它的方法和需求不匹配时（方法结果相同或相似），不是软件设计阶段考虑的设计模式，是随着软件维护，由于不同产品、不同厂家造成功能类似而接口不相同的情况下的解决方案

优点：能提高类的透明性和服用，现有的类复用但不需要改变，目标类和适配器类解耦，提高程序扩展性，符合开闭原则

缺点：适配器编写过程需要全面考虑，可能会增加系统的复杂性，增加系统代码可读的难度

```
public class Adaptee {
    public void adapteeRequest() {
        System.out.println("被适配者的方法");
    }
}

public interface Target {
    void request();
}

public class ConcreteTarget implements Target {
    @Override
    public void request() {
        System.out.println("ConcreteTarget目标方法");
    }
}

public class Adapter extends Adaptee implements Target {
    @Override
    public void request() {
        super.adapteeRequest();
    }
}

public class Test {
    public static void main(String[]args){
        Target target = new ConcreteTarget();
        target.request();

        Target adapterTarget = new Adapter();
        adapterTarget.request();
    }
}
```

这里将Adaptee的adapteeRequest方法适配成类request方法，减少了对类型对判断和对原有类对修改


### 享元模式
定义：提供了减少对象数量从而改善应用所需的对象结构的方式

运用共享技术有效地支持大量细粒度的对象

类型：结构型

适用场景：常常应用于系统底层的开发，以便解决系统的性能问题，系统有大量类似对象、需要缓冲池的场景

优点：减少对象的创建，降低内存中对象的数量，降低系统的内存，提高效率，减少内存之外的其他资源占用

缺点：关注内/外部状态、关注线程安全问题，使系统、程序的实现复杂化

```
public interface Employee {
    void report();
}

public class Manager implements Employee {
    private String department;
    private String reportContent;
    public Manager(String department) {
        this.department = department;
    }
    public void setReportContent(String reportContent) {
        this.reportContent = reportContent;
    }
    @Override
    public void report() {
        System.out.println(reportContent);
    }
}

public class EmployeeFactory {
    private static final Map<String, Employee> EMPLOYEE_MAP = new HashMap<>();

    public static Employee getManager(String department) {
        Manager manager = (Manager) EMPLOYEE_MAP.get(department);
        if (manager == null) {
            manager = new Manager(department);
            System.out.println("创建部门经理"+department);
            String reportContent = department+"部门汇报:此次报告的主要内容是......";
            manager.setReportContent(reportContent);
            System.out.println("    创建报告"+reportContent);
            EMPLOYEE_MAP.put(department, manager);
        }
        return manager;
    }
}

public class Test {
    private static final String departments[] = {"RD","QA","PM","BD"};

    public static void main(String[]args){
        for (int i = 0; i < 10; i++) {
            String department = departments[(int) (Math.random() * departments.length)];
            Manager manager = (Manager) EmployeeFactory.getManager(department);
        }    
    }
}
```

对象创建后继续利用，不再重新创建

### 组合
定义：将对西那个组合成树形结构以表示"整体-部分"的层次结构

组合模式使客户端对单个对象和组合对象保持一致的方式处理

类型：结构型

适用场景：希望客户端可以忽略组合对象与单个对象的差异，处理一个树形结构

优点：清楚地定义分层次的复杂对象，表示对象的全部或部分层次，让客户端忽略了层次的差异，方便对整个层次结构进行控制，简化了客户端代码，符合开闭原则

缺点：限制类型时会较为复杂，使设计变得更加抽象

```
public abstract class CatalogComponent {
    public void add(CatalogComponent catalogComponent) {
        throw new UnsupportedOperationException("不支持添加操作");
    }
    public void remove(CatalogComponent catalogComponent) {
        throw new UnsupportedOperationException("不支持删除操作");
    }
    public String getName(CatalogComponent catalogComponent) {
        throw new UnsupportedOperationException("不支持获取名称操作");
    }
    public double getPrice(CatalogComponent catalogComponent) {
        throw new UnsupportedOperationException("不支持获取价格操作");
    }
    public void print() {
        throw new UnsupportedOperationException("不支持打印操作");
    }
}

public class Course extends CatalogComponent{
    private String name;
    private double price;

    public Course(String name, double price) {
        this.name = name;
        this.price = price;
    }

    @Override
    public String getName(CatalogComponent catalogComponent) {
        return this.name;
    }

    @Override
    public double getPrice(CatalogComponent catalogComponent) {
        return this.price;
    }

    @Override
    public void print() {
        System.out.println("Course Name :"+name+" price"+price);
    }
}

public class CourseCatalog extends CatalogComponent {
    private List<CatalogComponent> items = new ArrayList<>();

    private String name;

    public CourseCatalog(String name) {
        this.name = name;
    }

    @Override
    public void add(CatalogComponent catalogComponent) {
        items.add(catalogComponent);
    }

    @Override
    public void remove(CatalogComponent catalogComponent) {
        items.remove(catalogComponent);
    }

    @Override
    public void print() {
        for (CatalogComponent catalogComponent : items) {
            catalogComponent.print();
        }
    }
}

public class Test {
    public static void main(String[]args){
        CatalogComponent linuxCourse = new Course("Linux课程", 11);
        CatalogComponent windowsCourse = new Course("windows课程", 11);

        CatalogComponent javaCourseCatalog = new CourseCatalog("Java课程目录");
        CatalogComponent mmallCatalog1 = new Course("Java电商一期",55);
        CatalogComponent mmallCatalog2 = new Course("Java电商二期",66);
        CatalogComponent designPattern = new Course("Java设计模式",77);

        javaCourseCatalog.add(mmallCatalog1);
        javaCourseCatalog.add(mmallCatalog2);
        javaCourseCatalog.add(designPattern);

        CatalogComponent ldcMainCourseCatalog = new CourseCatalog("网站课程主目录");
        ldcMainCourseCatalog.add(linuxCourse);
        ldcMainCourseCatalog.add(windowsCourse);
        ldcMainCourseCatalog.add(javaCourseCatalog);

        ldcMainCourseCatalog.print();
    }
}
```

将课程和目录组合成一个部分，不必太过区分彼此对用法

### 桥接
定义：将抽象部分与他的具体实现部分分离，使他们都可以独立地变化

通过组合的方式建立两个类之间的联系，而不是继承

类型：结构型

适用场景

* 抽象和具体实现之间增加更多的灵活性
* 一个类存在两个（或多个）独立变化的纬度，且这两个（或多个）纬度都需要独立进行扩展
* 不希望适用继承，或因为多层继承导致系统类的个数剧增

优点：分离抽象部分及其具体实现部分，提高了系统的可扩展性，符合开闭原则，符合合成复用原则

缺点：增加了系统的理解与设计难度，需要正确地识别出系统中两个独立变化的纬度

```
public interface Account {
    Account openAccount();
    void showAccountType();
}

public abstract class Bank {
    protected Account account;
    public Bank(Account account) {
        this.account = account
    }
    abstract Account openAccount();
}
```

这里Account是具体的实现，Bank是抽象，抽象类的某个行为委托给Account

```
public class ABCBank extends Bank {
    public ABCBank(Account account) {
        super(account);
    }
    @Override
    Account openAccount() {
        System.out.println("打开ABC银行账号");
        account.openAccount();
        return account;
    }
}

public class Test {
    public static void main(String[]args){
        Bank abcBank = new ABCBank(new Account());
        Account abcAccount = abcBank.openAccount();
        abcAccount.showAccountType();
    }
}
```

### 代理
定义：为其他对象提供一种代理，以控制对这个对象对访问

代理对象在客户端和目标对象之间起到中介作用

类型：结构型

适用场景：保护目标对象，增强目标对象

优点：代理模式能将代理对象和真实被调用对目标对象分离，一定程度上降低了系统的耦合，扩展性好，可以保护目标对象和增强目标对象

缺点：代理模式会造成系统设计中类的数目增加，在客户端和目标对象增加一个代理对象，会造成请求处理速度变慢，增加系统的复杂度

举例一个动态代理

```
public class OrderServiceDynamicProxy implements InvocationHanlder {
    private Object target;
    public OrderServiceDynamicProxy(Object target) {
        this.target = target;
    }
    public Object bind() {
        Class cls = target.getClass();
        return Proxy.newProxyInstance(cls.getClassLoader(), cls.getInterfaces(), this);
    }
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        Object argObject = args[0];
        beforeMethod(argObject);
        Object object = method.invoke(target, args);
        afterMethod();
        return Object;
    }
    public void beforeMethod(Object obj) {
    }
    public void afterMethod() {}
}
```

`Proxy.newProxyInstance`有三个参数

> loader(ClassLoader): 用哪个类加载器去加载代理对象

> interfaces(Class<?>[]):动态代理类需要实现的接口

> h(InvocationHandler):动态代理方法在执行时，会调用h里面的invoke方法去执行

这样，在运行的时候，调用原来类的每个方法，都会执行beforeMethod和afterMethod
 
```
{
    "target": {
        "host": [
            {"id": "xxx", "target": "127.0.0.1"},
            {"id": "xxx", "target": "127.0.0.1"}, ...],
        "domain": [
            {"id": "xxx", "target": "webank.com"},
            {"id": "xxx", "target": "webank.com"}, ...],
        "service": [
            {"id": "xxx", "target": "127.0.0.1:80"},
            {"id": "xxx", "target": "127.0.0.1:8080"}, ...],
        "request": [
            {"id": "xxx", "target": "https://127.0.0.1:80/?id=1"},
            {"id": "xxx", "target": "https://127.0.0.1:80/?id=1"}, ...]
    },
    "option": {
        **kwargs
    }
}
```

