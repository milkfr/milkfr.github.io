---
title: Python动态处理定时任务的生态与深坑
description: 记录一个寻找Python动态处理定时任务的过程，以及Python生态中celery、apscheduler的研究和使用问题，和最后在有很好开发设计能力的同事帮助下的一个解决过程，以及自己的反思
categories:
 - Python
tags:
 - Python
---


### 0x00 问题的起因
想在扫描器中加一个Web管理的任务调度模块，因为公司的隔离的网段很多，进行扫描任务如果每个都要配Crontab很麻烦，希望可以通过Web操作的配置直接修改定时任务的功能

细化一点就是

* 任务包含输入马上执行的一次性任务、定时执行一次性任务、间隔一定时间的定时任务
* 重要参数一是目标，也就是如何通过目标参数选定CMDB资产库中的资产
* 重要参数二是扫描参数，如何选择插件和插件参数
* 重要参数三是回调参数，如何在完成任务后处理结果

这里的难点在于

* 任务调度的处理的选型和使用
* 扫描器插件的多样化，有单目标单PoC的扫描插件，也就nmap这样一定要多个目标形成组才能扫描更快的工具，因此请求和返回的格式会不同，返回结果的处理上，也是有些告警，有些更新DB，处理种类多样

### 0x01 第一版及遇到的问题
#### celery的问题
首现选型上，网上一搜索就是Python界大红大紫的celery，一看文档和案例，这么方便处理异步调度的任务，第一印象就感觉很好，然后又有定时任务调度的功能，马上就敲定它了

在Flask的web中完全融入celery的内容，参考了Flask Web开发动物书作者的github公开项目[flasky-with-celery](https://github.com/miguelgrinberg/flasky-with-celery.git)

感觉生态真不错，真的用的人多，应该没什么问题，而且这里例子还支持任务进度的显示，感觉以后还可以加个任务进度条，美滋滋

但是很快就遇到了问题

这个celery支持的定时任务，只可以在启动的时候通过写的代码加载任务或者从配置文件中加载任务，它一点不动态，查询了一圈，有一个[django-celery-beat](https://github.com/celery/django-celery-beat.git)的项目完全支持我想要的功能，于是又拿起这个项目研究研究，看看能不能用flask实现一个，结果这个项目动态更新定时任务的方式是重启celery-beat

总是感觉重启的方式不是很优雅，所以我又放弃了看这个项目

然后网上搜啊搜啊搜，看到有人提出利用调用任务时候的eta参数，可以指定下一次任务调用的时间，然后可以任务完成后指定下一次任务调用时间

我觉得这个思路不错，flask启动的时候指定要调度的任务和时间，如果页面配置任务改了，就在取消原来的任务然后开一个新的定时任务，celery有根据ID取消任务的功能（revoke），配合celery的Signal是个不错的处理方式

#### celery中的Signal
可以看一下官方文档对Signal的示例

```
@after_task_publish.connect(sender='proj.tasks.add')
def task_sent_handler(sender=None, headers=None, body=None, **kwargs):
    # information about task are located in headers for task messages
    # using the task protocol version 2.
    info = headers if 'task' in headers else body
    print('after_task_publish for task id {info[id]}'.format(
        info=info,
    ))
```

celery提供了`before_task_publish,after_task_publish,task_prerun,task_postrun,task_retry,task_success,task_failure,task_received,task_revoked,task_unknown,task_rejected`这些在task生命周期中可以操作的方法

如文档示例，可以根据任务名（sender传入的值）进行定制，进行不同的处理这样可以根据不同的插件和任务参数在任务执行前后分别进行

* 前：根据参数选择目标和插件
* 后：根据参数选择callback和拿下执行的eta时间

然后又遇到了Signal的一个坑，Signal提供的方法中`before_task_publish和after_task_publish`可以根据sender名来处理，但是其他的方式不是

```
@after_task_publish.connect(sender='proj.tasks.add')
def task_sent_handler(sender=None, headers=None, body=None, **kwargs):
    print(type(sender))
    # do something
```

这里打印出不同的方法的sender，发现`before_task_publish`和`after_task_publish`的方法的sender是str，其他方法的类型是object，对任务的分类处理变得困难

查看代码，大概可以得出，开始任务是根据任务名来确定，然后开始任务生成了一个任务对象，之后是根据这个对象来确定的，这么大的不同文档里都没有提一句，网上的celery生态因为没有什么人使用signal，所有也没有什么解决办法

其实到这里还是有解决方式，比如传入task的参数中标明任务，然后根据任务object的这个参数进行判断，但是我又觉得一是这样前后的处理方式其实差很大的，这样写起来很奇怪，二是也不太敢用这个signal了，不知道哪里又会又什么问题

但是我还是尝试了一下，然后写着写着，一是实现起来通过eta很复杂，如果要减少代码，需要自己在好几个地方封装根据数据库的任务配置进行验证和修改，二是感觉celery提供的Signal的在任务前后进行处理的方式真的不是很好，三是考虑想到nmap这种如果扫描慢了超时，导致有一次定时任务没有按时开始执行，并因此少了日报会被领导批，所以又开始看看有没有其他方便到方式

其实上面第三个原因是我自己没有想清楚，但是写的心累，所以强行算理由

#### 之后的问题
之后我在寻找方法的过程中，又遇到三个问题

* 一个是原本运行celery突然查找不到任务，`celery_imports、celery_includes`这些，代码版本回退竟然还是查找不到，真的没有改代码，不知道发生了什么，网上能找到的方法都试了一遍，最后把celery的模块全部删除，照着原来的代码复制了一边，竟然好了
* 一个是task中不能再获取其他任务的结果，就是task中异步调用其他任务，不能等待任务返回结果，这个其实没太大问题，但是当时很想在一个任务中等待另一个任务的结果，现在想来是自己设计的不好
* 一个是尝试将rabbitmq换成redis时候出现很多错误，具体是什么忘记了，但是竟然不能像ORM一样无缝切换，觉得有些失望

这就让人觉得celery不好用了，原因是选型的时候用它，处理一些简单的任务没问题，但是有一些非常规的需求时，需要对它的文档很了解，而且熟读文档可能还是不行，因为比如signal的问题没有在文档中说明，要自己踩坑才会发现

总体来说，celery太重了，对熟悉会用的人来说很好用，对像我这种需要简单需求也没那么熟悉的人在选择上感觉还是不用它了，有些能找到问题所在但是也不敢再封装它也不敢改它代码

celery的github的issue中好像说以后5的大版本会支持动态定时任务

### 0x02 第二版和apscheduler的问题
我是真的觉得自己会折腾，celery不行之后，我就又在python生态中找了python-crontab、sched、apscheduler等一系列库

然后选中等apscheduler，为了不重蹈celery的覆辙，我把apscheduler的所有代码都看了一遍，觉得了然于胸

#### apscheduelr整体实现方式和扩展方式解读
apscheduler整体使用了组合和监听者模式，它分了scheduler、executor、jobstore、trigger几个模块

注意下面的代码只是我自己归纳的伪代码，和apschduler的真正实现无关

```
class Scheduler:

    def __init__(executor, jobstore):
        self.executor = executor
        self.jobstore = jobstore
    
    def start():
        self.executor.start()
        self.jobstore.start()
    
    def stop():
        self.executor.stop()
        self.jobstore.stop()

    def shutdown():
        self.executor.shutdown()
        self.jobstore.shutdown()
```

上面是组合模式的使用，start的时候上下文涵盖的对象全部start，然后stop、shutdown，可以做好对象的统一管理，统一创建和销毁

然后在start、stop、shutdown这些动作之后都会调用一个callback函数，用到scheduler的listener，根据这个listener包含的callback函数对apscheduler进行扩展

这是因为如果直接改动start、stop等方法，变动太大，所以apschduler就使用了监听者模式，将start、stop、执行任务等操作编程Event，事件触发或者完成是callback回调监听者注册的方法

```
class Schduler: 
    def start(self):
        # do something
        self._dispatch_event(SchedulerEvent(EVENT_SCHEDULER_RESUMED))

    def _dispatch_event(self, event):
            with self._listeners_lock:
                listeners = tuple(self._listeners)
            for cb, mask in listeners:
                if event.code & mask:
                    try:
                        cb(event)
                    except BaseException:
                        self._logger.exception('Error notifying listener')
```

然后apschduler对多进程、多线程、asyncio、gevent等python常用的调度方式进行了定制，非常方便，也很简单粗暴

于是我又选型apscheduler

#### gunicorn和apscheduler结合的深坑
然后我就按照apscheduler的API和flask进行了结合，很快完成了最开始的需求，开发环境完美测试通过

此时我还在沾沾自喜

然后上了测试环境，完全部署之后，配置gunicorn将app分成4个进程进行，然后悲剧来了

同一时间的定时任务执行了4次，当时直接网上找方法，使用了gunicorn的preload参数等，很快不执行4次了，但是改变定时任务时间后任务也不执行了

看来还得看本质，不能看表现，基本研究一下就是，一开始apscheduler跟随app在4个进程中，初始化4次，所以定时任务执行了4次，然后使用preload后，初始化一次，但是4个进程复制了4次，但是接收请求的进程不一定是开启的守护线程的那个scheduler，只能更新数据库，不能awake这个apscheduler

也就是说，我设计时没有考虑多进程的变量共享的问题

这样就要么一个进程执行，要么加锁

然后我剥离出了apscheduler作为一个单独的进程，用redis的pub/sub来传输flask app和apschduelr的任务变更的更新

我还是解决了这个问题，这里遇到一个小坑，就是apschduler的模块是组合模式，所以单个模块抽离出来是不能使用的，但也解决了

但是我感觉解决的不开心也没有成就感

### 0x03 三人行必有我师
很快我觉得写的越来越复杂，因为用apscheduler单独处理还是要对请求的目标、扫描器参数和回调方法做很多处理

我寻求周围同事、导师的帮助，和他们分享了一下这个问题，很明显，都是做渗透出身的，并不会开发，平时都是我教他们的。。。

只能找写Java的开发同事问问，找了个设计模式学得好的，果然术业有专攻，不会写Python也能说很清楚，他给我提了一些建议

1. 你的这个方式的主要问题就是太灵活了，因为灵活所以耦合就会很高
2. 不同的目标、插件和callback其实对应的参数是不一样的，强行放到一起让思路更加混乱，不如多分几个接口，每个接口单独处理，会少很多让思路混乱的地方
3. 你的这些参数解析其实还是会有很多插件的解析方式是一样的，只有少量插件需要特殊处理，不如你统一一下任务传输的格式，对需要特殊处理的插件先经过一层adapter，adapter对解析的方式规则变一下
4. 我建议你使用celery，既然社区推荐，而且你自己觉得它也很强大，只是不熟悉的人用不好，你需要克服这个
5. 其实还是最开始设计有问题，比如apscheduler的多进程问题，而你又想做得全又有点追求优雅，没这方面实践确实容易设计不好，经验比较重要
6. 实际上你可以回去审视最开始的需求，我觉得发版改配置不是很复杂，而且你的这些任务未必能做到你想要的那么灵活，配置任务后确保任务能跑通也是复杂度的来源，这么调控参数容易发生意想不到的错误，而且改的频率未必有你想要的那么高，是不是其实是个没必要的需求

### 0x04 最终版本
总结我一开始的需求同事说的对

* 要确保变更那么多参数但是不出问题其实就很复杂，定时任务的发版只会在有新的隔离的网段出现会存在，这个操作其实不频繁，可以牺牲一定的灵活性去满足生态中提供的方案和减少自己定制化思考
* 总结插件的类型，大部分是单目标但PoC的处理，少量批处理目标，回调也只有这些少量的不同，可以分离出来加adapter
* 再学学celery，看看它提供的处理方式有没有什么便利

因此，又设计了两个方案，一个是用apscheduler处理定时任务的动态调度，将任务发送给celery，celery处理参数和回调，一个是直接用celery，直接取消web处理任务的操作和动态定时任务的需求，用[celery-flower](https://flower-docs-cn.readthedocs.io/zh/latest/)提供的接口替代单次任务，用celery beat处理定时任务

第一种方案是解耦任务调度和参数处理，apscheduler的职责变得简单，只是触发一下任务，其他所有处理交给celery，优点是实现方便，可以动态调度

第二种方案是看看实际是否需要否定原来的需求，牺牲灵活来减少coder的工作，然后celery的监控还是可能需要用到celery-flower，没必要多个管理台，直接使用它的功能也很不错

celery提供继承的方式来进行任务的参数解析和回调处理

```
from celery import chord
from celery_worker import celery
import abc
from scanner.node import handle


class BaseHandleTask(celery.Task, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_target_list(self, target_option):
        pass

    @abc.abstractmethod
    def get_plugin_list(self, plugin_option):
        pass

    def run(self, target_option, plugin_option):
        print(target_option)
        print(plugin_option)
        target_list = self.get_target_list(target_option)
        plugin_list = self.get_plugin_list(plugin_option)
        print(target_list)
        print(plugin_list)
        tasks = []
        for plugin in plugin_list:
            for target in target_list:
                tasks.append(handle.s(target, plugin))
        chord(tasks)(self.get_success_callback().s().on_error(self.get_error_callback().s()))

    @abc.abstractmethod
    def get_success_callback(self):
        pass

    @abc.abstractmethod
    def get_error_callback(self):
        pass
```

最后实现了类似这样的抽象类，根据插件类型的区别，对目标和插件参数的解析去实现抽象方法，用celery的work-flow中的chord调用一组task并调用回调方法，回调方法也使用抽象方法定制

这样可以解耦参数的处理和回调，也不用考虑插件的输入输出的影响

经过一段时间实践，觉得还是放弃需求，该用第二种方法更加让人省心

### 0x04 总结
* 多请教别人，请比人吃饭，不要一个人钻牛角尖
* 经验确实不足，比如项目设计时就要考虑进程线程的问题，技术选型上等等，都要不断尝试，得到更好实践
* 整个遇坑和填坑的过程比较有进步，不亏