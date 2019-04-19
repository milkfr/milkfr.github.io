---
title: Python设计模式（结构型模式）
description: Python设计模式（结构型模式）
categories:
 - Python
tags:
 - Python
 - 设计模式
---

#### 结构型模式
* 装饰器模式（Decorator）：无需子类扩展对象功能
* 代理模式（Proxy）：把一个对象的操作代理到另一个对象
* 适配器模式（Adapter）：通过一个间接层适配统一接口
* 外观模式（Facade）：简化复杂对象的访问问题
* 享元模式（Flyweight）：通过对象复用（池）改善资源利用，比如连接池
* MVC模式：解耦展示逻辑和业务逻辑


### 装饰器模式
无论何时我们想对一个对象添加额外对功能有以下几种方法

* 如果合理，可以直接将功能添加到对象所属对类（添加一个新方法或者参数）
* 使用组合
* 使用继承
* 设计模式为我们提供第四种可选方法，支持动态地（运行时）扩展一个对象对功能，就是装饰器

```
def fibonacci(n):
    assert(n >= 0), 'n must be >= 0'
    return n if n in (0, 1) else fibonacci(n-1) + fibonacci(n-2)

from timeit import Timer
t = Timer('fibonacci(8)', 'from __main__ import fibonacci')
print(t.timeit())

>> 16.583633725065738
```

```
# memoization方案
known = {0:0, 1:1}
    def fibonacci(n):
        assert(n >= 0), 'n must be >= 0'
        if n in known:
            return known[n]
        res = fibonacci(n-1) + fibonacci(n-2)
        known[n] = res
        return res

if __name__ == '__main__': 8 from timeit import Timer
t = Timer('fibonacci(100)', 'from __main__ import fibonacci')
print(t.timeit())

>> 0.23158301785588264
```

```
# 装饰器版本
import functools

def memoize(fn):
    known = dict()
    
    @functools.wraps(fn)  # 可以继承__name__和__doc__
    def memoizer(*args):
        if args not in known:
            known[args] = fn(*args)
        return known[args]
    
    return memoizer

@memoize
def fibonacci(n):
    assert(n >= 0), 'n must be >= 0'
    return n if n in (0, 1) else fibonacci(n-1) + fibonacci(n-2)
    
```

### 代理模式
* 远程代理：实际存在于不同地址空间（例如，某个网络服务器）的对象在本地的代理者
* 虚拟代理：用于懒初始化，将一个大计算量对象的创建延迟到真正需要的时候进行
* 保护/防护代理：控制对敏感对象的访问
* 智能（引用）代理：在对象被访问时执行额外的动作，此类代理的例子包括引用技术和线程安全检查
* ORM

```
class SensitiveInfo:
    def __init__(self):
        self.users = ['nick', 'tom', 'ben', 'mike']
    
    def read(self):
        print('There are {} users: {}'.format(len(self.users), ' '.join(self.users)))
    
    def add(self):
        self.users.append(user)
        print('Added user {}'.format(user))

class Info:
    def __init__(self):
        self.protected = SensitiveInfo()
        self.secret = '0xdeadbeef'
    
    def read(self):
        self.protected.read()
    
    def add(self, user):
        sec = input('what is secret? ')
        self.protected.add(user) if sec == self.secret else print('That is wrong!')
    
def main():
    info = Info()
```

### 适配器模式
* 在无需修改不兼容模型的源代码就能获得接口的一致性

```
class Synthesizer:
    def __init__(self, name):
        self.name = name
    
    def play(self):
        return 'is playing an electronic song'

class Human:
    def __init__(self, name):
        self.name = name
    
    def speak(self):
        return 'say hello'

class Computer:
    def __init__(self, name):
        self.name = name
    
    def execute(self):
        return 'executes a program'

class Adapter:
    def __init__(self, obj, adapted_methods):
        self.obj = obj
        self.__dict__.update(adapted_methods)
    

def main():
    objects = [Computer('Asus')]
    synth = Synthesizer('moog')
    objects.append(Adapter(synth, dict(execute=synth.play)))
    human = Human('bob')
    objects.append(Adatper(human, dict(execute=human.speak)))
    
    for i in objects:
        print('{} {}'.format(str(i), i.execute()))
```

### 外观模式
本质上，外观是在已有复杂系统之上实现一个抽象层

```
from enum import Enum
from abc import ABCMeta, abstractmethod

State = Enum('State', 'new running sleeping restart zombie')

class User:
    pass

class Process:
    pass

class File:
    pass

class Server(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self):
        passs
    
    def __str__(self):
        return self.name
    
    @abstractmethod
    def boot(self):
        pass
    
    @abstractmethod
    def kill(self, restart=True):
        pass

class FileServer(Server):
    def __init__(self):
        self.name = 'FileServer'
        self.state = State.new
    
    def boot(self):
        print('Killing {}'.format(self))
        self.state = State.running
    
    def kill(self, restart=True):
        print('Killing {}'.format(self))
        self.state = State.restart if restart else State.zombie
    
    def create_file(self, user, name, permissions):
        print('trying to create the file {} for user {} with permissions {}'.format(name, user, permissions)    

class ProcessServer(Server):
    def __init__(self):
        self.name = 'ProcessServer'
        self.state = State.new
    
    def boot(self):
        print('booting the {}'.format(self))
        self.state = State.running
    
    def kill(self, restart=True):
        print('Killing {}'.format(self))
        self.state = State.restart if restart else State.zombie
    
    def create_process(self, user, name):
        print('trying to create the process {} for user {}'.format(name, user))

class OperatingSystem:
    def __init__(self):
        self.fs = FileServer()
        self.ps = ProcessServer()
    
    def start(self):
        [i.boot() for i in (self.fs, self.ps)]
    
    def create_file(self, user, name, permissions):
        return self.fs.create_file(user, name, permissions)
    
    def create_process(self, user, name):
        return self.ps.create_process(user, name)

def main():
    os = OperatingSystem()
    os.start()
    os.create_file('foo', 'hello', '-rw-r-r')
    os.create_process('bar', 'ls /tmp')
```

### 享元模式
* 享元模式通过为相似对象引入数据共享来最小化内存使用，提升性能
* 一个享元就是一个包含状态独立的不可变（又称固有的）数据的共享对象
* 依赖状态的可变（又称非固有的）数据不应是享元的一部分，因为每个对象的这种信息不同，无法共享
* 享元模式旨在优化性能和内存使用，一般满足以下几个条件时有效
    * 应用需要使用大量对象
    * 对象太多，存储/渲染它们代价太大，一旦移除对象中的可变状态（因为在需要之时，应该由客户端代码显式地传递给享元），多组不同的对象可被相对更少的共享对象替代
    * 对象ID对于应用不重要，对象共享会造成ID比较的失败，所以不能依赖对象ID（那些在客户端代码看来不同的对象，最终具有相同的ID）

```
import random
from enum import Enum

TreeType = Enum('TreeType', 'apple_tree cherry_tree peach_tree')

class Tree:
    pool = dict()
    
    def __new__(cls, tree_type):
        obj = cls.pool.get(tree_type, None)
        if not obj:
            obj = object.__new__(cls)
            cls.pool(tree_type) = obj
            obj.tree_type = tree_type
        return obj
    
    def render(self, age, x, y):
        print('render a tree of type {} and age {} at ({}, {})'.format(self,tree_type, age, x, y))
    
def main():
    rnd = random.Random()
    age_min, age_max = 1, 30
    min_point, max_point = 0, 100
    tree_counter = 0
    
    for _ in range(10):
        t1 = Tree(TreeType.apple_tree)
        t1.render(rnd.randint(age_min, age_max),
                  rnd.randint(min_point, max_point),
                  rnd.randint(min_point, max_point))
        tree_counter += 1
        
    for _ in range(3):
        t1 = Tree(TreeType.cherry_tree)
        t1.render(rnd.randint(age_min, age_max),
                  rnd.randint(min_point, max_point),
                  rnd.randint(min_point, max_point))
        tree_counter += 1
        
    for _ in range(5):
        t1 = Tree(TreeType.peach_tree)
        t1.render(rnd.randint(age_min, age_max),
                  rnd.randint(min_point, max_point),
                  rnd.randint(min_point, max_point))
        tree_counter += 1
```

### MVC模式
* 关注点分离（Separation of Concerns, SoC）原则是软件工厂相关设计原则之一
* 一般GUI常用，不太用到
* 一般需要确保创建的模型很智能、控制器很瘦、视图很傻瓜
* 智能模型
    * 包含所有的校验/业务规则/逻辑
    * 处理应用的状态
    * 访问应用数据（数据库、云或其他）
    * 不依赖UI
* 瘦控制器
    * 在用户和视图交互时，更新模型
    * 在模型改变时，更新视图
    * 如果需要，在数据传递给模型/视图之前进行处理
    * 不展示数据
    * 不直接访问应用数据
    * 不包含校验/业务规则/逻辑
* 傻瓜视图
    * 展示数据
    * 允许用户与其交互
    * 仅做最小的数据处理，通常由一种模版语言提供处理能力（例如简单的变量和循环控制）
    * 不存储任何数据
    * 不直接访问应用数据
    * 不包含校验/业务规则/逻辑

