---
title: 扫描器里的动态爬虫的一些实践（三）
description: 根据猪猪侠在先知白帽大会的PPT写的爬虫，实践过一段时间后的心得体会
categories:
 - 安全开发 
tags:
 - 安全开发
---

承接前两篇

[扫描器里的动态爬虫的一些实践（一）](https://milkfr.github.io/%E5%AE%89%E5%85%A8%E5%BC%80%E5%8F%91/2018/12/20/dev-heuristic-crawl-1/)

[扫描器里的动态爬虫的一些实践（二）](https://milkfr.github.io/%E5%AE%89%E5%85%A8%E5%BC%80%E5%8F%91/2018/12/21/dev-heuristic-crawl-2/)

其实前两篇写完了，写这篇的主要原因是使用pyppeteer在前两篇的一些例子失效了，主要是在页面加载前注入js代码里hook一些BOM的函数无效了

真的蛮烦人的，看GitHub上pyppeteer也不怎么更新，毕竟非官方的项目，感觉要凉

所以尝试使用其他方式，我选用[pychrome](https://github.com/fate0/pychrome)，这篇记录一下怎么尝试，怎么解决问题，毕竟授人以渔最好

### 0x00 环境搭建
我是mac上的环境

下载chromium并启动CDP模式

```
$ /Users/milkfr/Library/Application\ Support/pyppeteer/local-chromium/575458/chrome-mac/Chromium.app/Contents/MacOS/Chromium --remote-debugging-port=9222
```

这样当我们启动pychrome就可以在页面上用开发者模式查看了

写一个简单的hook setTimeout的例子

```
import pychrome
import pychrome.exceptions

browser = pychrome.Browser(url='http://127.0.0.1:9222')
# 保持一个标签
tab = browser.list_tab()[0]
tab.start()
tab.Page.enable()
tab.Page.addScriptToEvaluateOnNewDocument(source="""
window.setTimeout = function() {
    arguments[0]()
};
""")
tab.Page.navigate(url="http://localhost:8333/test.html")
tab.wait(60)
```

test.html的内容 

```
<html>
	<header>
	</header>
	<body>
		<script>
            var i = 0;
            setTimeout(function () {
				i+=1;
				alert(i);
			}, 3000)
		</script>
	</body>
</html>
```

运行之后会立即弹框，没有等待时间了

### 0x01 如何写上面这个例子
我公司里有一个高手同事，写了几年腾讯扫描器，因为腾讯业务多，案例多，据说他半年能写10篇专利

他跟我说，好的爬虫大家都自己留着，谁会开源出来

他跟我说，动态爬虫其实爬取不是什么问题，主要是一些特例行为会阻断、拦截，处理好这些行为就可以，就能写比较好的爬虫了

所以我问他要爬虫代码，他不给，我说给我点例子，让我自己研究总可以了吧，他说自己写demo，写案例

可是我都没遇到多少这样的案例啊

简单说就是case要多才能写好，解决case的过程就是进步的过程，就是强化爬虫的过程，没case就是没有用

#### 先来一个小case
就是上面test.html的页面

```
<html>
	<header>
	</header>
	<body>
		<script>
            var i = 0;
            setTimeout(function () {
				i+=1;
				alert(i);
			}, 3000)
		</script>
	</body>
</html>
```

首先要知道，我们的目标就是要在页面加载前hook住`setTimeout`函数

我们的pyppeteer的`page.evaluateOnNewDocument`失效了，所以我们要赚到pychrome这个库

#### 如何确定API
我们首先肯定是要写几个Demo熟悉一下这迁移到的这个库pychrome

但其实我们可以发现，官方文档只有一个README，和一个docker运行的chrome headless环境，如何知道我们要使用什么API去hook呢

首先我们都知道不管外部的接口是什么样的，但是我们知道操作chrome headless都是使用的CDP，在爬虫第一篇文章里说过了

pychrome是对CDP的封装，而虽然pyppeteer是对puppeteer的Python非官方版本，但是puppeteer还是操作的CDP，只不过提供高级接口而已

也就是说，我们想要从pyppeteer中迁移什么功能到pychrome中，只需要找到pyppeteer最终使用了CDP的什么接口就可以了

#### 寻找evaluateOnNewDocument的CDP接口

```
async def evaluateOnNewDocument(self, pageFunction: str, *args: str
                                ) -> None:
    """Add a JavaScript function to the document.

    This function would be invoked in one of the following scenarios:

    * whenever the page is navigated
    * whenever the child frame is attached or navigated. In this case, the
      function is invoked in the context of the newly attached frame.
    """
    source = helper.evaluationString(pageFunction, *args)
    await self._client.send('Page.addScriptToEvaluateOnNewDocument', {
        'source': source,
})
```

可以看到这里使用的是`Page.addScriptToEvaluateOnNewDocument`接口

然后我们到[CDP文档](https://chromedevtools.github.io/devtools-protocol/)中寻找接口

```
Page.addScriptToEvaluateOnNewDocument
#
Evaluates given script in every frame upon creation (before loading frame's scripts).

PARAMETERS
    source string
    worldName string If specified, creates an isolated world with the given name and evaluates given script in it. This world name will be used as the ExecutionContextDescription::name when the corresponding event is emitted.
RETURN OBJECT
    identifier ScriptIdentifier Identifier of the added script.
```

查看明白之后，不要怂，就是试，就有了我们上面这句

```
tab.Page.addScriptToEvaluateOnNewDocument(source="""
window.setTimeout = function() {
    arguments[0]()
};
""")
```

#### 总结
大概就是这样把原来用pyppeteer写的功能一个个转过来

有些pyppeteer到CDP的接口还有一部分Python封装，会麻烦一些，比如waitUntil就难实现一些

转换是个大工程，我感觉我要完蛋