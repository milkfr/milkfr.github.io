---
title: Python的werkzeug框架源码分析（一）
description: Python的werkzeug框架的源码分析第一篇，环境是Python3，werkzeug的1.0.0.dev0版本
categories:
 - Python
tags:
 - Python
 - werkzeug
---

### 程序结构
```
werkzeug
    debug
        shared
        __init__.py
        console.py
        repr.py
        tbtools.py
    middleware
        __init__.py
        dispatcher.py
        http_proxy.py
        lint.py
        profiler.py
        proxy_fix.py
        shared_data.py
    wrappers
        __init__.py
        accept.py
        auth.py
        base_request.py
        base_response.py
        common_descriptors.py
        etag.py
        json.py
        request.py
        response.py
        user_agent.py
    __init__.py
    _compat.py
    _internal.py
    _reloader.py
    datastructures.py
    exceptions.py
    filesystem.py
    formparser.py
    http.py
    local.py
    posixemulation.py
    routing.py
    security.py
    serving.py
    test.py
    testapp.py
    urls.py
    useragents.py
    utils.py
    wsgi.py
```
      

### `__init__.py`
实际上第一次看`__init__`疑惑了很久，因为实在不知道这里使用`lazy-loading module`的作用是什么

一般情况下延迟加载模块的好处是为了需要时加载，减少内存占用，坏处是，在代码中进行加载，如果出错会中途停止程序，而不是在程序启动时候就提示

一般采用在方法中加载模块和使用`importlib.import_module`的方式进行加载，如下

```
# 函数运行完被回收
def fake():
    import fake
    fake.fake()

# a变量回收后被回收
a = importlib.import_module('fake')
a.fake()
```

以官网最简单的例子来说，是使用了`from werkzeug.wrappers import Request, Response`，并不会用到延时加载，而是直接加载

基本只有在以下情况才会触发延时加载模块的功能，但是并不知道什么时候会用到，不知道这里模块懒加载有什么作用，可能在包内部模块实现的时候使用？

```
In [1]: import werkzeug
In [2]: werkzeug.Request
Out[2]: werkzeug.wrappers.Request
In [3]: a = werkzeug.Request  # a回收后引用回收，werkzeug保存一次引用
```

`__init__.py`的核心就是`lazy-loading module`，下面来看下它的实现

```
# 这个很多只截取了一部分
all_by_module = {
    "werkzeug.serving": ["run_simple"],
    "werkzeug.wrappers": [
        "Request",
        "Response",
    ],
    ......
}

# modules that should be imported when accessed as attributes of werkzeug
attribute_modules = frozenset(["exceptions", "routing"])

object_origins = {}
for module, items in all_by_module.items():
    for item in items:
        object_origins[item] = module
# object_origins = { 
#     "run_simple": "werkzeug.serving",
#     "Request": "werkzeug.wrappers",
#     "Response": "werkzeug.wrappers",
#     ......
# }

# 核心类
class module(ModuleType):
    """Automatically import objects from the modules."""

    # __getattr__方法是在要获取类成员时，不存在才调用，存在就调用__getattribute__方法，不在进入此方法
    def __getattr__(self, name):
        if name in object_origins:
            module = __import__(object_origins[name], None, None, [name])
            for extra_name in all_by_module[module.__name__]:
                setattr(self, extra_name, getattr(module, extra_name))
            return getattr(module, name)
        elif name in attribute_modules:
            __import__("werkzeug." + name)
        return ModuleType.__getattribute__(self, name)

    def __dir__(self):
        """Just show what we want to show."""
        result = list(new_module.__all__)
        result.extend(
            (
                "__file__",
                "__doc__",
                "__all__",
                "__docformat__",
                "__name__",
                "__path__",
                "__package__",
                "__version__",
            )
        )
        return result

# keep a reference to this module so that it's not garbage collected
old_module = sys.modules["werkzeug"]

# setup the new module and patch it into the dict of loaded modules
new_module = sys.modules["werkzeug"] = module("werkzeug")
new_module.__dict__.update(
    {
        "__file__": __file__,
        "__package__": "werkzeug",
        "__path__": __path__,
        "__doc__": __doc__,
        "__version__": __version__,
        "__all__": tuple(object_origins) + tuple(attribute_modules),
        "__docformat__": "restructuredtext en",
    }
)

# 导入就会报错的化需要用到
__import__("werkzeug.exceptions")
```

我们要知道，访问类成员会调用魔术方法`__getattribute__`，如果成员不存在，调用`__getattribute__`方法后会调用`__getattr__`方法，所以这里在`__getattr__`方法中引用了模块，之后通过名字调用就直接通过`__getattribute__`方法了，模块只引用一次

```
import werkzeug

werkzeug.Request  # 调用__getattr__，第一次引入werkzeug.wrappers模块
werkzeug.Response  # 不调用，Request和Response同属于werkzeug.wrappers模块，上面调用之后无需调用
werkzeug.run_simple  # 调用__getattr__，run_simple在werkzeug.serving中，需要调用一次
```

这里`__init__.py`中会在实现中需要使用方法和类的时候加载模块，模块的一个引用保存在werkzeug中


### A simple example
按照官网例子，先看懂这个

```
from werkzeug.wrappers import Request, Response

@Request.application
def application(request):
    return Response('Hello, World!')

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple('localhost', 4000, application)
```


