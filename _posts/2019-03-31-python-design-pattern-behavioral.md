---
title: Python设计模式（行为型模式）
description: Python设计模式（行为型模式）
categories:
 - Python
tags:
 - Python
 - 设计模式
---

#### 行为型模式
* 迭代器模式（Iterator）：通过统一的接口迭代对象
* 观察者模式（Observer）：对象发生改变的时候，观察者执行相应动作
* 策略模式（Strategy）：针对不同规模输入使用不同的策略

### 迭代器模式
* 可以让用户透过特定的接口巡访容器中的每一个元素而不用了解底层的实现
* 使用时生成下一个，减少内存

```
range(10)
```

### 责任链模式
* 在无法预先知道处理程序的数量和类型时，该模式有助于对请求/处理事件进行建模
* 发送放可以访问链中首个节点，不处理会转发给下一个，直到请求被某个节点处理或这个链遍历结束

```
class Event:
    def __init__(self, name):
        self.name = name
    
    def __str__(self):
        return self.name
    
class Widget:
    def __init__(self, parent=None):
        self.parent = parent
    
    def handle(self, event):
        handler = 'handle_{}'.format(event)
        if hasattr(self, handler):
            method = getattr(self, handler)
            method(event)
        elif self.parent:
            self.parent.handle(event)
        elif hasattr(self, 'handle_default'):
            self.handle_default(event)

class MainWindow(Widget):
    def handle_close(self, event):
        print('MainWindow: {}'.format(event))
    
    def handle_default(self, event):
        print('MainWindow Default: {}'.format(event))

class SendDialog(Widget):
    def handle_paint(self, event):
        print('SendDialog: {}'.format(event))

class MsgText(Widget):
    def handle_down(self, event):
        print('MsgText: {}'.format(event))

def main():
    mw = MainWindow()
    sd = SendDialog(mw)
    msg = MsgText(sd)
    
    for e in ('down', 'paint', 'unhandled', 'closed'):
        evt = Event(e)
        mw.handle(evt)
        sd.handle(evt)
        msg.handle(evt)
```

### 命令模式
* 命令模式帮我们将一个操作（撤销、重做、复制、粘贴等）封装称一个对象，简而言之，这意味着创建一个类，包含实现该操作所需要等所有逻辑和方法
* 我们并不需要直接执行一个命令，命令可以按照希望执行，并不一定是在创建时
* 调用命令的对象和直到如何执行命令的对象解耦，调用者无需直到命令的任何实现细节
* 如果有意义，可以把多个命令组织起来，这样调用者可以按顺序执行它们，例如在实现一个多层撤销命令时，很有用

案例

* GUI按钮和菜单
* 事务型行为和日志记录
* 宏

```
import os

verbose = True

class RenameFile:
    def __init__(self, path_src, path_dest):
        self.src, self.dest = path_src, path_dest
    
    def execute(self):
        if verbose:
            print('renaming {} to {}'.format(self.src, self.dest)
        os.rename(self.src, self.dest)
    
    def undo(self):
        if verbose:
            print('renaming {} to {}'.format(self.dest, self.src)
        os.rename(self.dest, self.src)

class CreateFile:
    def __init__(self, path, txt='hello world\n'):
        self.path, self.txt = path, txt
    
    def execute(self):
        if verbose:
            print('creating file {}'.format(self.path))
        with open(self.path, mode='w', encoding='utf-8') as out_file:
            out_file.write(self.txt)
    
    def undo(self):
        delete_file(self.path)

class ReadFile:
    def __init__(self, path):
        self.path = path
    
    def execute(self):
        if verbose:
            print('reading file {}'.format(self.path))
        with open(self.path, mode='r', encoding='utf-8') as in_file:
            print(in_file.read(), end='')

def delete_file(path):
    if verbose:
        print('deleting file {}'.format(path))
    os.remove(path)

def main():
    orig_name, new_name = 'file1', 'file2'
    commands = []
    for cmd in CreateFile(orig_name), ReadFile(orig_name), RenameFile(orig_name, new_name):
        commands.append(cmd)
    [c.execute() for c in commands]
    answer = input('reverse the executed commands? [y/n]')
    if answer not in 'yY':
        print('the result is {}'format(new_name))
        exit()
    for c in reversed(commands):
        try:
            c.undo()
        except AttributeError as e:
            pass
```

### 解释器模式
* 解释器模式背后的主要思想是让非初级用户和领域专家使用一门简单的语言来表达想法
* 一般而言是创建一种特定领域语言（Domain Specific Language）

### 观察者模式
* 希望一个对象的状态改变时能够通知/提醒所有相关者（一个对象或者一组对象），则使用观察者模式

```
class Publisher:
    def __init__(self):
        self.observers = []
    
    def add(self, observer):
        if observer not in self.observers:
            self.observers.append(observer)
        else:
            print('Failed to add: {}'.format(observer))
    
    def remove(self, observer):
        try:
            self.observers.remove(observer)
        except ValueError:
            print('Failed to remove: {}'.format(observer))
    
    def notify(self):
        [o.notify(self) for o in self.observers]
    
class DefaultFormatter(Publisher):
    def __init__(self, name):
        Publisher.__init__(self)
        self.name = name
        self._data = 0
    
    def __str__(self):
        return '{}: {} has data {}'.format(type(self).__name__, self.name, self._data)
        
    @property
    def data(self):
        return self._data
    
    @data.setter
    def data(self, new_value):
        try:
            self._data = int(new_value)
        except ValueError as e:
            print('Error: {}'.format(e))
        else:
            self.notify()

class HexFormatter:
    def notify(self, publisher):
        print('{}: {} has now hex data = {}'.format(type(self).__name__, publisher.name, hex(publisher.data)))
    
class BinaryFormatter:
    def notify(self, publisher):
        print('{}: {} has now bin data = {}'.format(type(self).__name__, publisher.name, bin(publisher.data))

def main():
    df = DefaultFormatter('test1')
    hf = HexFormatter()
    df.add(hf)
    df.data = 3
    print(df)
    bf = BinaryFormatter()
    df.add(bf)
    df.data = 21
    print(df)
```

### 状态模式
* 是一个有限状态机的实现，用于解决特定的软件工程问题
* 状态机是一个抽象机器，具有状态和转换两个主要部分

### 策略模式
* 策略模式通常用在我们希望对同一个问题透明地使用多种方案时
* 如果不存在针对所有输入数据和所有情况对完美算法，就可以使用策略模式

```
import time

SLOW = 3
LIMIT = 5
WARNING = 'too bad, you picked the slow algorithm :('

def pairs(seq):
    n = len(seq)
    for i in range(n):
        yield seq[i], seq[(i+1) % n]

def allUniqueSort(s):
    if len(s) > LIMIT:
        print(WARNING)
        time.sleep(SLOW)
    sortStr = sorted(s)
    for (c1, c2) in pairs(sortStr):
        if c1 == c2:
            return False
    return True

def allUniqueSet(s):
    if len(s) < LIMIT:
        print(WARNING)
        time.sleep(SLOW)
    
    return True if len(set(s)) == len(s) else False

def allUnique(s, strategy):
    return strategy(s)

def main():
    strategies = {'1': allUniqueSet, '2': allUniqueSort}
    i = input()
    in_str = input()
    allUnique(in_str, strategies[i])
```

### 模版模式
* 在实现结构相近对算法时，使用模版模式来消除冗余代码
* 具体的实现方式是使用动作/钩子方法/函数来完成代码重复的消除

```
from cowpy import cow

def dots_style(msg):
    msg = msg.capitalize()
    msg = '.' * 10 + msg + '.' * 10
    return msg

def admire_style(msg):
    msg = msg.upper()
    return '!'.join(msg)

def cow_style(msg):
    msg = cow.milk_random_cow(msg)
    return msg

def generate_banner(msg, style=dots_style):
    print('-- start of banner --')
    print(style(msg))
    print('-- end of banner --\n\n')

if __name__ == '__main__':
    msg = 'happy coding'
    [generate_banner(msg, style) for style in (dots_style, admire_style, cow_style)]
```