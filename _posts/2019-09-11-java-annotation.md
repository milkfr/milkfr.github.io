---
title: Java的注解
description: 之前学Struts2的时候源码里用到了注解，用来将对象注入到容器中，看了个似懂非懂，如今重新学习一遍
categories:
 - Java
tags:
 - Java
---

### 0x00 注解例子
#### 写一个注解
```
import java.lang.annotation.Retention;
        import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface MyAnnotation {
    String getValue() default "no description";
}
```

#### 使用一个注解
```
@MyAnnotation(getValue = "annotation on class")
public class User {
    @MyAnnotation(getValue = "annotation on field")
    public String name;

    @MyAnnotation(getValue = "annotation on method")
    public void hello() {}
}
```

#### 获取一个注解
```
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Test {
    public static void main(String[] args) throws Exception {
        Class<User> clazz = User.class;
        MyAnnotation annotationOnClass = clazz.getAnnotation(MyAnnotation.class);
        System.out.println(annotationOnClass.getValue());

        Field name = clazz.getField("name");
        MyAnnotation annotationOnField = name.getAnnotation(MyAnnotation.class);
        System.out.println(annotationOnField.getValue());

        Method hello = clazz.getMethod("hello", null);
        MyAnnotation annotationOnMethod = hello.getAnnotation(MyAnnotation.class);
        System.out.println(annotationOnMethod.getValue());
    }
}
```

#### 说明
一般像我这样的Python程序员，看到这个注解，想到的肯定是Python里的装饰器，但是实际上，这两者基本没有什么关系

如果对一个方法使用了注解，然后调用方法，会发现注解没有任何装饰器的作用，和我们上面获取一个注解的方式一样，Java里的注解主要是用来被非注解的方法调用，一般是通过反射的方式，也就是在调用方法前，获取它的注解并操作注解的内容

Java里的注解就像标签，是程序判断执行的依据，比如`@Before`就是在测试方法之前执行

`@Retention(RetentionPolicy.RUNTIME)`是元注解，就是加在注解上的注解，`Rentention`用来指定注解的保留策略

因为注解主要被反射读取，反射执行读取内存中的字节码信息，保留策略设置为`RUNTIME`，可以运行时读取，如果不设置，会报错，不信可以去掉`@Retention(RententionPolicy.RUNTIME)`尝试一下

大多数情况下，我们只需要使用注解，无需定义和执行，框架会将注解类和读取注解的程序隐藏起来，不阅读源码不知道注解怎么使用

### 0x01 模拟框架的注解
#### 写几个注解
```
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface MyBefore {
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface MyTest {
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface MyAfter {
}
```

#### 使用注解
```
public class User {
    @MyBefore
    public void init() {
        System.out.println("init");
    }

    @MyAfter
    public void destroy() {
        System.out.println("destroy");
    }

    @MyTest
    public void testSave() {
        System.out.println("save");
    }

    @MyTest
    public void testDelete() {
        System.out.println("delete");
    }
}
```

#### 框架如何调用注解
```
public class Test {
    public static void main(String[] args) throws Exception {
        Class clazz = User.class;
        Object obj = clazz.newInstance();
        Method[] methods = clazz.getMethods();

        List<Method> myBeforeList = new ArrayList<Method>();
        List<Method> myAfterList = new ArrayList<Method>();
        List<Method> myTestList = new ArrayList<Method>();

        for (Method method : methods) {
            if (method.isAnnotationPresent(MyBefore.class)) {
                myBeforeList.add(method);
            } else if (method.isAnnotationPresent(MyTest.class)) {
                myTestList.add(method);
            } else if (method.isAnnotationPresent(MyAfter.class)) {
                myAfterList.add(method);
            }
        }

        for (Method testMethod : myTestList) {
            for (Method beforeMethod : myBeforeList) {
                beforeMethod.invoke(obj);
            }
            testMethod.invoke(obj);
            for (Method afterMethod : myAfterList) {
                afterMethod.invoke(obj);
            }
        }
    }
}
```

执行结果

```
init
save
destroy
init
delete
destroy
```

自己写一遍体会一下就能明白

通过反射获取一个类，获取类中的方法和属性，根据方法和属性的注解和注解的参数进行一些判断处理操作
