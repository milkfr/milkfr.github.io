---
title: Java Web研习二：背一些设计模式
description: 创建型模式
categories:
 - Java Web
tags:
 - Java Web
---


### 简单工厂
定义：由一个工厂对象决定创建出哪一种产品类的实例

类型：创建型，但不属于GOF23中设计模式

试用场景：工厂类负责创建的对象比较少，客户端（应用层）只知道传入工厂类的参数，对于如何创建对象（逻辑）不关心

优点：只需要传入一个正确的参数，就可以获取你所需要的对象而无需知道其创建细节

缺点：工厂类的指责相对过重，增加新的产品，需要修改工厂类的判断逻辑，违背开闭原则


举例

一个简单工厂的应用代码
```
public class Test {
    public static void main(String[] args) {
        BookFactory bookFactory = new BookFactory();
        Book book = bookFactory.getBook("java");
        if (book == null) {
            return;
        }
        book.read();
    }
}
```

简单工厂内容入下
```
public class BookFactory {
    public Book getBook(String type) {
        if ('java'.equalsIgnoreCase(type)) {
            return new JavaBook();
        } else if ('python'.equalsIgnoreCase(type)) {
            return new PythonBook();
        }
        return null
    }
}
```

应用不需要关注简单工厂类的内容，但是如果需要增加的新的课程，就需要添加扩展工厂类，增加if判断，不符合开闭原则

利用Java的反射机制可以演进一下，使他在一定程度上符合开闭原则

```
public class VideoFactory {
    public Vdieo getVideo(Class clazz) {
        Book book = null;
        try {
            book = (Book) Class.forName(clazz.getName()).newInstance();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return book;
    }
}
```

### 工厂方法
定义：定义一个创建对象的接口，但让实现这个接口的类来决定实例化哪个类，工厂方法让类的实例化推迟到子类中进行

类型：创建型

试用场景：创建对象需要大量重复的代码，客户端（应用层）不依赖于产品类实例如何被创建、实现等细节，一个类通过其子类来指定创建哪个对象

优点：用户只需要关系所需产品对应等工厂，无需关系创建细节，加入新产品符合开闭原则，提高可扩展性

缺点：类的个数容易过多，增加复杂度，增加了系统的抽象性和理解难度

举例

可以将简单工厂类改成一个抽象类

```
public abstract class BookFactory {
    public abstract Book getBook();
}
```

创建一些继承这个抽象工厂类的子工厂类

```
public class PythonBookFactory extends BookFactory {
    @Override
    public Book getBook() {
        return new PythonBook();
    }
}

public class JavaBookFactory extends BookFactory {
    @Override
    public Book getBook() {
        return new JavaBook();
    }
}
```

应用类
```
public class Test {
    public static void main(String[] args){
        BookFactory bookFactory = new JavaBookFactory();
        Book book = bookFactory.getBook();
        book.read();
    }
}
```

需要创建什么，就创建一个相应对象的工厂

抽象工厂是子类具体实现的工厂，抽象产品是子类的具体的产品


### 抽象工厂
定义：抽象工厂模式提供一个创建一系列相关或相互依赖对象的接口

无须指定他们的类

类型：创建型

适用场景：

* 客户端（应用层）不依赖于产品类实例如何被创建、实现等细节
* 强调一系列相关的产品对象（属于统一产品族）一起使用创建对象需要大量重复代码
* 提供一个产品类的库，所有的产品以同样的接口出现，从而使客户端不依赖于具体实现

优点：具体产品在应用层代码隔离，无须关系创建细节，将一系列产品族统一到一起创建

缺点：规定了所有可能被创建的产品集合，产品族中扩展新的产品困难，需要修改抽象工厂的接口，增加类系统的抽象性和理解难度

工厂方法和抽象工厂的不同：

工厂方法模式针对的是产品等级结构（同一个产品，比如Book）

抽象工厂模式针对的是产品族（课堂为一个族，Book，Pen，Teacher是不同的产品等级结构）

理论上讲：当一个工厂可以创建出分属于不同产品等级结构的一个产品族中的所有对象时，那这个时候，抽象工厂模式要比工厂方法模式更为简单，更有效率

举例

课堂类

```
public interface CourseFactory {
    Book getBook();
    Pen getPen();
}
```

某个产品族

```
public class JavaCourseFactory implements CourseFactory {
    @Override
    public Book getBook() {
        return JavaBook();
    }
    
    @Override 
    public Pen getPen() {
        return JavaPen();
    }
}
```

应用层代码

```
public class Test {
    public static void main(String[]args){
        CourseFactory courseFactory = new JavaCourseFactory();
        Pen pen = courseFactory.getPen();
        Book book = courseFactory.getBook();
        pen.write();
        book.read();
    }
}
```

在使用抽象工厂的时候，尽量找那种固定程度比较高的，像课程里面的视频和手记，视频和手记都是必须要有的，就可以用抽象工厂模来解决


### 建造者
定义：将一个复杂对象的结构与它的表示分离，使得同样的构建过程可以创建不同的表示

用户只需指定需要创建的类型就可以得到它们，建造过程及细节不需要知道

类型：创建型

适用场景：如果一个对象有非常复杂的内部结构（很多属性），想把复杂对象的创建和适用分离

优点：封装性好，创建和适用分离，扩展性好、建造者之间独立、一定程度上解耦

缺点：产生多余的Builder对象，产品内部发生变化，建造者都要修改，成本较大

举例

```
public class Course {
    
    private String courseName;
    private String coursePPT;
    private String courseVideo;
    private String courseArticle;
    private String courseQA;

    public Course(CourseBuilder courseBuilder) {
        this.courseName = courseBuilder.courseName;
        this.coursePPT = courseBuilder.coursePPT;
        this.courseVideo = courseBuilder.courseVideo;
        this.courseArticle = courseBuilder.courseArticle;
        this.courseQA = courseBuilder.courseQA;
    }

    public static class CourseBuilder{
        private String courseName;
        private String coursePPT;
        private String courseVideo;
        private String courseArticle;
        private String courseQA;

        public CourseBuilder builderCourseName(String courseName) {
            this.courseName = courseName;
            return this;
        }
        public CourseBuilder builderCoursePPT(String coursePPT) {
            this.coursePPT = coursePPT;
            return this;
        }
        public CourseBuilder builderCourseVideo(String courseVideo) {
            this.courseVideo = courseVideo;
            return this;
        }
        public CourseBuilder builderCourseArticle(String courseArticle) {
            this.courseArticle = courseArticle;
            return this;
        }
        public CourseBuilder builderCourseQA(String courseQA) {
            this.courseQA = courseQA;
            return this;
        }

        public Course build() {
            return new Course(this);
        }
    }

    @Override
    public String toString() {
        return "Course{" +
                "courseName='" + courseName + '\'' +
                ", coursePPT='" + coursePPT + '\'' +
                ", courseVideo='" + courseVideo + '\'' +
                ", courseArticle='" + courseArticle + '\'' +
                ", courseQA='" + courseQA + '\'' +
                '}';
    }
}
```

应用处

```
public class Test {
    public static void main(String[]args){
        Course course = new Course.CourseBuilder()
                .builderCourseName("Java设计模式")
                .builderCoursePPT("Java设计模式PPT")
                .builderCourseVideo("Java设计模式视频")
                .builderCourseArticle("Java设计模式手记")
                .builderCourseQA("Java设计模式问答").build();
        System.out.println(course);
    }
}
```

### 单例模式
定义：保证一个类仅有一个实例，并提供一个全局访问点

类型：创建型

适用场景：想确保任何情况下都绝对只有一个实例

优点：在内存里只有一个实例，减少了内存开销，可以避免对资源对多重占用，设置全局访问点，严格访问控制

缺点：没有接口，扩展困难

单例模式重点：私有构造器，线程安全，延迟加载，序列化和反序列化，反射

### 原型
定义：指原型实例指定创建对象的种类，并且通过拷贝这些原型创建新的对象

不需要知道任何创建的细节，不调用构造函数

类型：创建型

适用场景

* 类初始化消耗较多资源
* new产生的一个对象需要非常繁杂的过程（数据准备、访问权限等）
* 构造函数比较复杂
* 循环体中生产大量对象时

优点：原型模式性能比直接new一个对象性能高，简化创建过程

缺点：必须配备克隆方法，对克隆复杂对象或对克隆出的对象进行复杂改造时，容易引入风险，深拷贝浅拷贝要运用得当

