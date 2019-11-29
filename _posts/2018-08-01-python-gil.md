---
title: Python-GIL
description: Python-GIL
categories:
 - Python
tags:
 - Python
---

### 引子
在2核4线程mac mini执行以下代码
```
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed


def countdown(num):
    while num > 0:
        num -= 1


n = 100000000

# single thread
start = time.time()
countdown(n)
end = time.time()

print('single thread:', end - start)
start = time.time()

# multi thread
with ThreadPoolExecutor(max_workers=4) as executor:
    t1 = executor.submit(countdown, n // 4)
    t2 = executor.submit(countdown, n // 4)
    t3 = executor.submit(countdown, n // 4)
    t4 = executor.submit(countdown, n // 4)
    for future in as_completed([t1, t2, t3, t4]):
        pass
end = time.time()
print('multi thread:', end-start)

# multi process
start = time.time()

with ProcessPoolExecutor(max_workers=4) as executor:
    p1 = executor.submit(countdown, n // 4)
    p2 = executor.submit(countdown, n // 4)
    p3 = executor.submit(countdown, n // 4)
    p4 = executor.submit(countdown, n // 4)
    for future in as_completed([p1, p2, p3, p4]):
        pass

end = time.time()
print('multi process', end-start)
```

输出为
```
single thread: 6.451351165771484
multi thread: 6.530150890350342
multi process 4.211022853851318
```

修改多进程多线程个数为两个，输出为
```
single thread: 8.322726964950562
multi thread: 9.010904788970947
multi process 4.903674125671387
```

多次测试多结果为单线程和多线程时间相差不大，也没有网上大多测试结果一样多线程会明显慢，应该说各有输赢，多进程明显快，worker数量为2或者4影响不大


### GIL简述
GIL是最流行的Python解释器CPython中的一个技术术语，意思是全局解释锁，本质上是类似操作系统的Mutex，每一个Python进程，在CPython解释器中执行时，都会先锁住自己的线程，阻止别的线程执行

### 为什么需要GIL
CPython使用引用计数来管理内存
```
In [1]: import sys
In [2]: a = []
In [3]: b = a
In [4]: sys.getrefcount(a)
Out[4]: 3
```
如上例子中a、b和getrefcount三个地方使用到了空列表，所以引用计数为3

如上例子中，如果两个线程同时引用了a，会造成引用计数到race condition，引用计数最终只增加1，当一个线程结束时，引用计数减少1，释放a的内存，当第二个线程再访问时就访问不到了

引入GIL的原因是

* 为了规避类似内存管理这样的复杂的竞争风险问题
* CPython大量使用C语言库，但大部分C语言库都不是原生线程安全的（线程安全会降低性能和增加复杂度）

### 怎么实现
整体来说，每一个Python线程都是类似如下代码的循环的封装
```
for (;;) {
    if (--ticker < 0) {
        ticker = check_interval;
        
        /* Givve another thread a chance %/
        PyThread_release_lock(interpreter_lock)
        
        /* Other threads may run now */
        
        PyThread_acquire_lock(interpreter_lock, 1);
    }
    bytecode = *next_instr++;
    switch (bytecode) {
        /* execute the next instruction ... */
    }
}
```

Thread轮流执行，每一个线程在开始时，会锁住GIL，阻止别的线程执行，CPython解释器会轮训检查线程GIL的锁住情况，每隔一段时间，Python解释器就会强制当前线程去释放GIL

上面的`check_interval`在不同版本的实现方式不同，早期是100个tickets，大致1000个bytecodes，Python3以后是15毫秒，官方会在一个"合理"的范围内释放

### Python的线程安全
执行如下代码，发现线程不安全

```
import threading

n = [0]


def foo():
    for _ in range(1000000):
        n[0] += 1


threads = []

for i in range(50):
    t = threading.Thread(target=foo)
    threads.append(t)

for t in threads:
    t.start()

for t in threads:
    t.join()

print(n)  // 多次执行输出[4114073]/[5000000]/[4613585]...
```

和网上大部分例子只执行`n += 1`不同，在我的电脑上触发不了线程不安全的问题（runoob的在线解释器可以），猜测可能是Python3中GIL切换要15ms，单个函数必须执行15ms以上才会切换导致线程不安全问题，所以改用了上面的代码，单个函数中执行很多次`n+=1`

通过Python的dis分析字节码
```

import dis

def update_list(l):
    l[0] = 1

dis.dis(update_list)
# 以下是输出
 2            0 LOAD_CONST               1 (1)
              2 LOAD_FAST                0 (l)
              4 LOAD_CONST               2 (0)
              6 STORE_SUBSCR  # 单字节码操作，线程安全
              8 LOAD_CONST               0 (None)
             10 RETURN_VALUE

def incr_list(l):
    l[0] += 1
    
dis.dis(incr_list)
# 以下是输出
  2           0 LOAD_FAST                0 (l)
              2 LOAD_CONST               1 (0)
              4 DUP_TOP_TWO
              6 BINARY_SUBSCR
              8 LOAD_CONST               2 (1)
             10 INPLACE_ADD  # 需要多个字节码操作，有可能在线程执行过程中切换到其他线程
             12 ROT_THREE
             14 STORE_SUBSCR
             16 LOAD_CONST               0 (None)
             18 RETURN_VALUE
```

对于上面代码，需要用锁来保证线程安全

```
def foo():
    with lock:
        for _ in range(1000000):
            n[0] += 1
```

总结：GIL的设计，主要是为了方便CPython解释器层面的编写者，而不是Python应用层面的程序员，CPython使用简单的锁避免多个线程执行字节码，但是一行Python代码不一定是一个字节码操作，并非Python中的原子操作，就容易造成线程不安全的问题

### 进程、线程和协程
从上面计算密集型的例子中可以看出，Python中单线程和多线程能力基本一致，多进程就更快

那几个问题

1. 多核的机器用Java、C这些语言多线程和多进程哪个更快，进程、线程和协程的开销到底多大，影响多大，核心数和进程数、线程数有什么关系
2. 如果内存足够、带宽足够，跑满CPU，Python线程和协程哪个更快
3. Linux系统的epoll和协程有关系吗