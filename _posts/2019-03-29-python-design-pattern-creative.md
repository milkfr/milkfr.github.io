---
title: Python设计模式（创建型模式）
description: Python设计模式（创建型模式）
categories:
 - Python
tags:
 - Python
 - 设计模式
---


#### 创建型模式
* 工厂模式（Factory）：解决对象创建问题
* 构造模式（Builder）：控制复杂对象的创建
* 原型模式（Prototype）：通过原型的克隆创建新的实例
* 单例模式（Brog/Singleton）：一个类只能创建同一对象
* 对象池模式（Pool）：预先分配同一类型的一组实例
* 惰性计算模式（Lazy Evaluation）：延迟计算（Python的property）


### 工厂模式
考虑自己是代码编写者，他人是代码使用者的情况下

让对方传入参数来请求对象，无需知晓对象实现，可以顺利使用对象

使用在以下场景

* 想要追踪对象的创建时
* 想要将对象的创建和使用解耦时
* 想要优化应用的性能和资源占用时

不懂这些，追踪对象是什么意思，如果将`s = SQLConnect(MySQL:uri)`改成`s = SQLConnect(SQLite:uri)`和将`s = MySQLConnect(uri)`改成`s = SQLiteConnect(uri)`有什么不同呢，之后都可以调用`s.connect`方法，如果用户要改变参数，就应该知道有什么不同了，对象都是用户创建，不管有没有工厂方法，用户创建几个对象就占多少空间，有什么区别呢

#### 工厂方法
````


