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
* 构造者模式（Builder）：控制复杂对象的创建
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

不懂这些，追踪对象是什么意思，如果将`s = SQLConnect(MySQL:uri)`改成`s = SQLConnect(SQLite:uri)`和将`s = MySQLConnect(uri)`改成`s = SQLiteConnect(uri)`有什么不同呢，之后都可以调用`s.connect`方法，如果用户要改变参数，本来就应该知道有什么不同了，对象都是用户创建，不管有没有工厂方法，用户创建几个对象就占多少空间，有什么区别呢

#### 工厂方法
```
import xml.etree.ElementTree as etree
import json

class JSONConnector:
    def __init__(self, filepath):
        self.data = dict()
        with open(filepath, mode='r', encoding='utf-8') as f:
            self.data = json.load(f)
    
    @property
    def parsed_data(self):
        return self.data

class XMLConnector:
    def __init__(self, filepath):
        self.tree = etree.parse(filepath)
    
    @property
    def parsed_data(self):
        return self.tree

def connection_factory(filepath):
    if filepath.endswith('json'):
        connector = JSONConnector
    elif filepath.endswith('xml'):
        connector = XMLConnector
    else:
        raise ValueError('Cannot connect to {}'.format(filepath))
    return connector(filepath)

def connect_to(filepath):
    factory = None
    try:
        factory = connection_factory(filepath)
    except ValueError as ve:
        print(ve)
    return factory

def main():
    json_factory = connect_to('data/person.json')
    json_data = json_factory.parsed_data
    
    xml_factory = connect_to('data/person.xml')
    xml_data = xml_factory.parsed_data
```

之后返回的数据进行处理最好也是用相同的代码方法，但是大多数时候不现实

工厂方法的设计模式的实现是一个不属于任何类的单一函数，负责某一种类的创建

#### 抽象工厂
* 是工厂模式的一种泛化
* 让对象的创建更容易追踪
* 将对象创建和使用解耦
* 提供优化内存占用和应用性能的潜力
* 通常一开始使用工厂方法，因为它更简单，如果后来发现应用需要许多的工厂方法，将创建一系列对象的过程合并在一起，从而最终引入抽象工厂
* 抽象工厂有一个优点，在使用工厂方法时从用户视角通常是看不到的，就是抽象工厂能够通过改变激活的工厂方法动态地（运行时）改变应用行为

```
class Frog:
    def __init__(self, name):
        self.name = name
        
    def __str__(self):
        return self.name
    
    def interact_with(self, obstacle):
        print('{} the Frog encounters {} and {}!'.format(self, obstacle, obstacle.action()))
   

class Bug:
    def __str__(self):
        return 'a bug'
    
    def action(self):
        return 'eats it'

class FrogWorld:
    def __init__(self, name):
        print(self)
     
    def __str__(self):
        return '\n\nt------ Frog World ------'
    
    def make_character(self):
        return Frog(self.player_name)
    
    def make_obstacle(self):
        return Bug()

class Wizard:
    def __init__(self, name):
        self.name = name
    
    def __str__(self):
        return self.name
    
    def interact_with(self, obstracle):
        print('{} the Wizard battles against {} and {}!'.format(self, obstacle, obstacle.action()))

class Ork:
    def __str__(self):
        return 'an evil ork'
    
    def action(self):
        return 'kills it'

class WizardWorld:
    def __init__(self, name):
        print(self)
        self.player_name = name
    
    def __str__(self):
        return '\n\n\t ------ Wizard World ------'
    
    def make_character(self):
        return Wizard(self.player_name)
    
    def make_obstacle(self):
        return Ork()

class GameEnvironment:
    def __init__(self, factory):
        self.hero = factory.make_character()
        self.obstacle = factory.make_obstacle()
    
    def play(self):
        self.hero.interact_with(self.obstacle)

def validate_age(name):
    try:
        age = input('Welcome {}. How old are you? '.format(name))
        age = int(age)
    except ValueError as err:
        print('Age {} is invalid, please try again...'.format(age))
        return (False, age)
    return (True age)

def main():
    name = input("Hello. What's your name? ")
    valid_input = False
    while not valid_input:
        valid_input, age = validate_age(name)
    game = FrogWorld if age < 18 else WizardWorld
    environment = GameEnvironment(game(name))
    environment.play()
```

GameEnvironment方法是类创建的工厂，类的`make_character`和`make_obstacle`是子类创建的工厂

抽象工厂设计模式的实现是同属于单个类的许多个工厂方法用于创建一系列种类的相关对象

### 建造者模式
* 建造者模式将一个复杂对象的构造过程与其表现分离，同一个构造过程可用于创建多个不同的表现
* 存在建造者(builder)和指挥者(director)两个部分，建造者负责创建复杂对象的各个组成部分，指挥者使用一个建造者实例控制建造的过程
* 工厂模式以单个步骤创建对象，而建造者模式以多个步骤创建对象，并且几乎始终使用一个指挥者

```
from enum import Enum
import time

PizzaProgress = Enum('PizzaProgress', 'queued preparation baking ready')
PizzaDough = Enum('PizzaDough', 'thin thick')
PizzaSauce = Enum('PizzaSauce', 'tomato creme_fraiche')
PizzaTopping = Enum('PizzaTopping', 'mozzarella double_mozzarella bacon ham mushrooms red_onion oregano')
STEP_DELAY = 3

class Pizza:
    def __init__(self, name):
        self.name = name
        self.dough = None
        self.sauce = None
        self.topping = []
    
    def __str__(self):
        return self.name
    
    def prepare_dough(self, dough):
        self.dough = dough
        print('preparing the {} dough of your {}...'.format(self.dough.name, self))
        time.sleep(STEP_DELAY)
        print('done with the {} dough'.format(self.dough.name))

Class MargaritaBuilder:
    def __init__(self):
        self.pizza = Pizza('margarita')
        self.progress = PizzaProgress.queued
        self.baking_time = 5
    
    def prepare_dough(self):
        self.progress = PizzaProgress.preparation
        self.pizza.prepare_dough(PizzaDough.thin)
    
    def add_sauce(self):
        print('adding the tomato sauce to your margarita...')
        self.pizza.sauce = PizzaSauce.tomato
        time.sleep(STEP_DELAY)
        print('done with the tomato sauce')
    
    def add_topping(self):
        print('adding the topping (double mozzarella, oregano) to your margarita')
        self.pizza.topping.append([i for i in (PizzaTopping.double_mozzarella, PizzaTopping.oregano)])
        time.sleep(STEP_DELAY)
        print('done with the topping (double mozzarella, oregano)')
    
    def bake(self):
        self.progress = PizzaProgress.baking
        print('baking your margarita for {} seconds'.format(self.baking_time))
        time.sleep(self.baking_time)
        self.progress = PizzaProgress.ready
        print('your margarita is ready')

class CreamyBaconBuilder:
    def __init__(self):
        self.pizza = Pizza('creamy bacon') 
        self.progress = PizzaProgress.queued 
        self.baking_time = 7 
        
    def prepare_dough(self):
        self.progress = PizzaProgress.preparation
        self.pizza.prepare_dough(PizzaDough.thick)
        
    def add_sauce(self):
        print('adding the crème fraîche sauce to your creamy bacon')
        self.pizza.sauce = PizzaSauce.creme_fraiche
        time.sleep(STEP_DELAY)
        print('done with the crème fraîche sauce')
        
    def add_topping(self):
        print('adding the topping (mozzarella, bacon, ham,
        mushrooms, red onion, oregano) to your creamy bacon') self.pizza.topping.append([t for t in (PizzaTopping.mozzarella, PizzaTopping.bacon,
        PizzaTopping.ham,PizzaTopping.mushrooms,
        PizzaTopping.red_onion, PizzaTopping.oregano)])
        time.sleep(STEP_DELAY)
        print('done with the topping (mozzarella, bacon, ham, mushrooms, red onion, oregano)')
        
    def bake(self):
        self.progress = PizzaProgress.baking
        print('baking your creamy bacon for {} seconds'.format(self.baking_time)) time.sleep(self.baking_time)
        self.progress = PizzaProgress.ready
        print('your creamy bacon is ready')

class Waiter:
    def __init__(self):
        self.builder = None
        
    def construct_pizza(self, builder):
        self.builder = builder
        [step() for step in (builder.prepare_dough, builder.add_sauce, builder.add_topping, builder.bake)]
    
    @property
    def pizza(self):
        return self.builder.pizza

def validate_style(builders):
    try:
        pizza_style = input('What pizza would you like, [m]argarita or [c]reamy bacon?')
        builder = builders[pizza_style]()
        valid_input = True
    except KeyError as err:
        print('Sorry, only margarita (key m) and creamy bacon (key c) are available')
        return (False, None)
    return (True, builder)

def main():
    builders = dict(m=MargaritaBuilder, c=CreamyBaconBuilder)
    valid_input = False
    while not valid_input:
        valid_input, builder = validate_style(builders)
    print()
    waiter = Waiter()
    waiter.construct_pizza(builder)
    pizza = waiter.pizza

# 变体，流利的建造者
class Pizza:
    def __init__(self, builder):
        self.garlic = build.garlic
        self.extra_cheese = builder.extra_cheese
    
    class PizzaBuilder:
        def __init__(self):
            self.extra_cheese = False
            self.garlic = False
        
        def add_garlic(self):
            self.garlic = True
            return self
        
        def add_extra_cheese(self):
            self.extra_cheese = True
            return self
        
        def build(self):
            return Pizza(self)

def main():
    pizza = Pizza.PizzaBuilder().add_garlic().add_extra_cheese().build()
    print(pizza)
```

与工厂模式对比，以下几种情况下，建造者模式更好

* 想创建一个复杂对象（对象由多个部分构成，且对象的创建要经过多个不同的步骤，这些步骤也许还需要遵循特定的顺序）
* 要求一个对象能有不同的表现，并希望将对象和构造与表现解耦
* 想要在某个时间点创建对象，但在稍后的时间点再访问

也就是将对象生成过程分离出来，将传入参数然后if、else判断的过程过程分离建造者类（固定的建造过程）和指挥者（参数接收者）？

### 原型模式
* 用于创建对象的完全副本
* 当创建一个浅副本时，副本依赖引用，关注性能和优化内存使用，在对象之间引用共享数据，数据修改共享
* 当创建一个深副本时，副本复制所有东西，更改不会数据共享，关注因对象克隆而引入资源耗用问题

```
import copy
from collections import OrderedDict

class Book:
    def __init__(self, name, authors, price, **rest):
        self.name
        self.authors = author
        self.price = price
        self.__dict__.update(rest)
    
    def __str__(self):
        mylist = []
        ordered = OrderedDict(sorted(self.__dict__.items()))
        for i in ordered.keys():
            mylist.append('{}: {}'.format(i, ordered[i]))
            if i == 'price':
                mylist.append('$')
            mylist.append('\n')
        return ''.join(mylist)

class Prototype:
    def __init__(self):
        self.objects = dict()
        
    def register(self, identifier, obj):
        self.objects[identifier] = obj
    
    def unregister(self, identifier):
        del self.objects[identifier]
    
    def clone(self, identifier, **attr):
        found = self.objects.get(identifier)
        if not found:
            raise ValueError('Incorrect object identifier: {}'.format(identifier)
        obj = copy.deepcopy(found)
        obj.__dict__.update(attr)
        return obj

def main():
    b1 = Book('The C Programming Language', ('Brian W. Kernighan', 'Dennis M.Ritchie'), price=110, publisher='Prentice Hall', length=228, publication_data='1978-02-22', tags=('C', 'programming', 'algorithms', 'data structures'))
    prototype = Prototype()
    cid = 'K&R first'
    prototype.register(cid, b1)
    b2 = prototype.clone(cid, name='The C Programming Language(ANSI)', price=48.00, length=274, publication_data='1988-04-01', edition=2)
```

Python中`copy.deepcopy()`函数完成深副本，普通情况下`=`即为浅副本


### 单例模式（Brog/Singleton）：一个类只能创建同一对象
* 一个类能返回对象一个引用（永远是同一个）和一个获得该实例的方法
* 单例模式在多线程使用中要小心，当唯一实例未创建时，两个线程同时调用方法就容易违背惟一实例原则，互斥锁可解（降低效率）

#### 模块实现
Python模块是天然单例模式，模块第一次导入时会生成pyc文件，第二次导入就直接加载pyc文件，而不会再次执行模块代码
```
# a.py
class Singleton(object):
    def foo(self):
        pass
singleton = Singleton()

# main.py
form a import singleton
```

#### 使用装饰器
```
def Singleton(cls):
    _instance = {}
    def _singleton(*args, **kwargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kwargs)
        return _instance[cls]
    return _singleton

@Singleton
class A(object):
    a = 1
    
    def __init__(self, x=0):
        self.x = x
a1 = A(2)
a2 = A(3)
```

#### 使用类，支持多线程
```
import threading

class Singleton(object):

    _instance_lock = threading.Lock()
    
    def __init__(self):
        pass  # time.sleep(1)

    @classmethod
    def instance(cls, *args, **kwargs):
        if not hasattr(Singleton, '_instance'):
            with Singleton._instance_lock:
                if not hasattr(Singleton, '_instance'):
                    Singleton._instance = Singleton(*args, **kwargs)
        return Singleton._instance
```

#### 基于`__new__`方法实现（方便推荐）
```
import threading

class Singleton:
    _instance_lock = threading.Lock()
    
    def __init__(self):
        pass
        
    def __new__(cls, *args, **kwargs):
        if no hasattr(Singleton, '_instance'):
            with Singleton._instance_lock:
                if not hasattr(Singleton, '_instance'):
                    Singleton._instance =super().__new__(cls)
        return Singleton._instance
```

#### 基于metaclass方式实现
```
improt threading

class SingletonType(type):
    _instance_lock = threading.Lock()
    def __call__(cls, *args, **kwargs):
        if not hasattr(cls, '_instance'):
            with SingletonType._instace_lock:
                if not hasattr(cls, '_instance'):
                    cls._instance = super(SingletonType.cls).__call__(*args, **kwargs)
        return cls._instance

class Foo(metaclass=SingletonType):
    def __init__(self, name):
        self.name = name 
```

### 对象池模式（Pool）：预先分配同一类型的一组实例
```
import Queue
import types
import threading
from contextlib import contextmanager

class ObjectPool(object):
    def __init__(self, fn_cls, *args, **kwargs):
        super(ObjectPool, self).__init__()
        self.fn_cls = fn_cls
        self._myinit(*args, **kwargs)
    
    def _myinit(self, *args, **kwargs):
        self.args = args
        self.maxSize = int(kwargs.get('maxSize', 1))
        self.queue = Queue.Queue()
    
    def _get_obj(self):
        if type(self.fn_cls) == types.FunctionType:
            return self.fn_cls(self.args)
        elif type(self.fn_cls) == types.ClassType or type(self.fn_cls) == types.TypeType:
            return apply(self.fn_cls, self.args)
        else:
            raise 'Wrong type'
    
    def borrow_obj(self):
        print self.queue._qsize()
        if self.queue.qsize() < self.maxSize and self.queue.empty():
            self.queue.put(self._get_obj())
        return self.queue.get()
    
    def recover_obj(self, obj):
        self.queue.put(obj)

def echo_func(num):
    return num

class echo_cls(object):
    pass

@contextmanager
def poolobj(pool):
    obj = pool.borrow_obj()
    try:
        yield obj
    except Exception, e:
        yield None
    finally:
        pool.recover_obj(obj)

obj = ObjectPool(echo_func, 23, maxSize=4)
obj2 = ObjectPool(echo_cls, maxSize=4)

class MyThread(threading.Thread):
    def run(self):
        with poolobj(obj) as t:
            print(t)
        with poolobj(obj2) as t:
            print(t)

if __name__ == '__main__':
    threads = []
    for i in range(200):
        t = MyThread()
        t.start()
        threads.append(t)
    for t in threads:
        t.join(True)
```

### 惰性计算模式（Lazy Evaluation）：延迟计算（Python的property）
```
def lazy_sum(*args):
    def sum():
        res = 0
        for i in args:
            res = res + i
        return res
    return sum

func = lazy_sum(1,2,3,4,5)
func()
```

```
# 延迟计算，算是缓存？
class LazyProperty(object):
    def __init__(self, func):
        self.func = func
    
    def __get__(self, instance, owner):
        if instance is None:
            return self
        else:
            value = self.func(instance)
            setattr(instance, self.func.__name__, value)
            return value

import math

class Circle(object):
    def __init__(self, radius):
        self.radius = radius
    
    @lazyProperty
    def area(self):
        print('computing area')
        return math.pi * self.radius ** 2
    
    @lazyProperty
    def perimeter(self):
        print('computing perimeter')
        return 2 * math.pi * self.radius
```
