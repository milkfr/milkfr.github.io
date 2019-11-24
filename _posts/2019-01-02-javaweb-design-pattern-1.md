---
title: Java Web研习二：背一些设计模式
description: 设计原则
categories:
 - Java Web
tags:
 - Java Web
---

### 开闭原则
定义：一个软件实体如类、模块和函数应该对扩展开放，对修改关闭

用抽象构建框架，用实现扩展细节

对扩展开放，意味着有新的需求或变化时，可以对现有代码进行扩展，以适应新的情况

对修改封闭，意味着类一旦设计完成，就可以独立完成其工作，而不要对类进行任何修改

优点：提高软件的可复用性及可维护性

例子
```
- com.github.milkfr.principle
    - openclose
        - ICourse
        - JavaCourse
        - Test
```

我们先设置一个命题，实现课程interface含有id、name、price属性，单个课程实现接口，使用处输出课程属性

```
package io.github.milkfr.principle.openclose;

public interface ICourse {
    Integer getId();
    String getName();
    Double getPrice();
}
```

```
package io.github.milkfr.principle.openclose;

public class JavaCourse implements ICourse {

    private Integer Id;
    private String name;
    private Double price;

    public JavaCourse(Integer id, String name, Double price) {
        this.Id = id;
        this.name = name;
        this.price = price;
    }

    @Override
    public Integer getId() {
        return this.Id;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public Double getPrice() {
        return this.price;
    }
}
```

```
package io.github.milkfr.principle.openclose;

public class Test {
    public static void main(String[] args) {
        ICourse javaCourse = new JavaCourse(97, "English", 10d);
        System.out.println(javaCourse.getId() + " | " + javaCourse.getName() + " | " + javaCourse.getPrice());
    }
}
```

需求变化时，需要在节日对JavaCourse等一些课程进行打折，不同课程折扣不同

一种方式是相关课程类修改价格，这样不打折或者🏠加优惠券等活动又要改回来，很麻烦

一种方式是ICourse增加一个打折方法，所有实现类也修改这个方法，虽然没有活动结束要改回来的要求，但所有实现接口不管打折不打折都要修改，接口应该稳定且可靠，不应该经常变化

一种方式是对这些课程实现一个子类处理打折需求

```
package io.github.milkfr.principle.openclose;

public class JavaDiscountCourse extends JavaCourse {
    public JavaDiscountCourse(Integer id, String name, Double price) {
        super(id, name, price);
    }

    @Override
    public Double getPrice() {
        return super.getPrice() * 0.8;
    }
}
```

```
package io.github.milkfr.principle.openclose;

public class Test {
    public static void main(String[] args) {
        ICourse iCourse = new JavaDiscountCourse(97, "English", 10d);
        JavaDiscountCourse javaCourse = (JavaDiscountCourse) iCourse;
        System.out.println(javaCourse.getId() + " | " + javaCourse.getName() + " | " + javaCourse.getPrice());
    }
}
```

这样做我们主要修改的是应用层的代码，减少底层ICourse的修改和部分实现类的修改，越底层被依赖的东西越多，修改起来越容易出问题

### 依赖倒置原则
定义：高层模块不应该依赖底层模块，二者都应该依赖其抽象

抽象不应该依赖细节，细节应该依赖抽象

针对接口编程，不要针对实现编程

优点：可以减少类间的耦合性，提高系统稳定性，提高代码可读性和可维护性，可降低修改程序所造成的风险

例子

```
- com.github.milkfr.principle
    - dependenceinversion
        - ICourse
        - JavaCourse
        - PythonCourse
        - Student
        - Test
```

先设置一个命题，一个学生需要学习一些课程，应用层代码如下
```
package io.github.milkfr.principle.dependenceinversion;

public class Test {
    public static void main(String[] args) {
        Student student = new Student();
        student.studyJavaCourse();
    }
}
```

```
package io.github.milkfr.principle.dependenceinversion;

public class Student {
    public void studyJavaCourse() {
        System.out.println("Java");
    }
}
```

如果学生要学习更多的课程，比如`studyPythonCourse`，我们就需要在Student类中加一个方法，需要学多少课程，就需要加多少方法，这样不如不要Stduent类，直接写到应用类中

```
package io.github.milkfr.principle.dependenceinversion;

public class Test {
    public static void main(String[] args) {
        Student student = new Student();
        student.study(new JavaCourse());
        student.study(new PythonCourse());
    }
}
```

```
package io.github.milkfr.principle.dependenceinversion;

public interface ICourse {
    void studyCouse();
}
```

```
package io.github.milkfr.principle.dependenceinversion;

public class JavaCourse implements ICourse {
    @Override
    public void studyCouse() {
        System.out.println("Java");
    }
}
```

```
package io.github.milkfr.principle.dependenceinversion;

public class Student {

    public void study(ICourse iCourse) {
        iCourse.studyCouse();
    }
}
```

这样修改后，Test是应用层，变更时必须修改，但是只要Student不修改，那么底层的课程类只需要扩展，而不需要修改

以抽象为基础搭建的架构要比以细节为基础搭建的架构稳定得多，因为细节多变，面向接口编程

### 单一职责原则
定义：不要存在多于一个导致类变更的原则

一个类/接口/方法只负责一项职责

优点：降低类的复杂度、提高类的可读性，提高系统的可维护性、降低变更引起的风险

这个其实比较好理解

比如动物类有叫这个功能，猫叫喵狗叫汪，就需要if-else判断猫狗，不如分成猫狗两个类

比如
```
public updateInfo(String name, boolean bool) {
    if (bool) {
        // todo something1
    } else {
        // todo something2
    }
}
```

这里其实boolean类型的变量不需要传进来，分成两个函数更好，bool判断放到上层

### 接口隔离原则
定义：用多个专门的接口，而不使用单一的总接口，客户端不应该依赖它不需要的接口

一个类对一个类的依赖应该建立在最小的接口上

建立单一接口，不要建立庞大臃肿的接口

尽量细化接口，接口中的方法尽量少

注意适度原则，一定要适度

优点：符合我们常说的高内聚低耦合的设计思想，从而使得类具有很好的可读性、可扩展性和可维护性

举例

```
public interface IAnimalAction {
    void eat();
    void swim();
    void fly();
}
```

比如Dog类实现IAnimalAction，但Dog不会fly，不如改成

```
public interface IFlyAnimalAction {
    void fly();
}

public interface IEatAnimalAction {
    void eat();
}
...
```

Dog继承Eat和Swim类

### 迪米特原则
定义：一个对象应该对其他对象保持最少的了解，又叫最少知道

尽量降低类与类之间的耦合，少公开public方法

优点：降低类之间的耦合

强调只和朋友交流，不和陌生人说话

朋友：出现在成员变量、方法的输入、输出参数中的类称为成员朋友类，而出现在方法体内部的类不属于朋友类

举例

```
public class School {
    public void checkStudentsNumber(Teacher teacher) {
        List<Student> studentList = new ArrayList<Student>();
        for (int i = 0; i < 20; i++) {
            studnetList.add(new Student());
        }
        teacher.checkNumberOfStudents(studentList);
    }
}
```

这里Teacher时朋友类，而Student不是，不如直接把Student都交给Teacher

```
public class Boss {
    public void checkStudentsNumber(Teacher teacher) {
        teacher.checkNumberOfStudents();
    }
}
```

### 里式替换原则
定义：如果对每一个类型为T1的对象O1，都有类型为T2的对象O2，使得以T1定义的所有程序P在所有对象O1都替换成O2时，程序P的行为没有发生变化，那么类型T2是类型T1的子类型

定义扩展：一个软件实体如果适用一个父类的化，那一定使用于其子类，所有引用父类的地方必须能透明地使用其子类的对象，子类对象能够替换父类对象，而程序逻辑不变

引申含义：子类可以扩展父类的功能，但不能个改变父类原有的功能

含义一：子类可以实现父类的抽象方法，但不能覆盖父类的非抽象方法

含义二：子类可以增加自己特有的方法

含义三：当子类的方法重载父类的方式时候，方法的前置条件（即方法的输入/输出）要比父类方法更宽松

含义四：当子类的方法实现父类的方法时（重写/重载或实现抽象方法），方法的后置条件（即方法的输出/返回值）要比父类更严格或相等

优点1：约束继承泛滥，开闭原则的一种体现

优点2：加强程序的健壮性，同时变更时也可以做到非常好的兼容性提高程序的维护性、扩展性，降低需求变更时引入的风险

举例：

比如上面开闭原则中的例子

```
package io.github.milkfr.principle.openclose;

public class JavaDiscountCourse extends JavaCourse {
    public JavaDiscountCourse(Integer id, String name, Double price) {
        super(id, name, price);
    }

    @Override
    public Double getPrice() {
        return super.getPrice() * 0.8;
    }
}
```

这里重写了父类的非抽象方法`getPrice`，违背了里氏替换原则，最好用`getDiscountPrice`方法替代

### 合成复用原则
定义：尽量使用对象组合/聚合，而不是继承关系达到软件复用的目的

聚合has-A、组合contains-A、继承is-A

优点：可以使系统更加灵活，降低类与类之间的耦合度，一个类的变化对其他类造成的影响相对较少

举例

一个连接数据库的类
```
public class DBConnection {
    public String getConnection() {
        return "DB Connection";
    }
}
```

它的子类
```
public class MySQLConnection extends DBConnection {
    @Override
    public String getConnection() {
        return "MySQL DB Connection";
    }
}
```

```
public class OracleConnection extends DBConnection {
    @Override
    public String getConnection() {
        return "Oracle DB Connection";
    }
}
```

一个Dao层

```
public class ProductDao {
    private DBConnection dbConnection;

    public void setDbConnection(DBConnection dbConnection) {
        this.dbConnection = dbConnection;
    }

    public void addProduct() {
        String conn = super.getConnection();
        System.out.println("use"+conn+"add product");
    }
}
```

应用层使用
```
public class Test {
    public static void main(String[]args){
        ProductDao productDao = new ProductDao();
        productDao.setDbConnection(new OracleConnection());
        productDao.addProduct();
    }
}
```

这样不用继承MySQLDaoConnection和OracleDaoConnection的方式可以减少Dao层对使用到conn的地方的修改，更加灵活，受到Connection的影响更小