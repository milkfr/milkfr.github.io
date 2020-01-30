---
title: 从一次入侵事件反思安全运营
description: 今年出现了一次安全事件，外网SSRF打到内网，第一次处理之后又发现第一次入侵时候到账号权限留存，可维持外网系统的权限的问题，先描述一下我对这两次事件的分析，然后谈谈我公司的安全运营
categories:
 - 总结与反思
tags:
 - 总结与反思
---

### 0x00 造成第一次入侵的事件背景
#### 简介
我们公司有一个从第三方企业采购差旅系统，就是员工出差进行购买机票酒店这些由公司报销的系统

这个系统有一个企业微信公众号，没错，我们公司用的企业微信，很垃圾，除了界面美化了一点完全不如以前腾讯的RTX

理论上这个公众号只要做好用户权限控制，跟企业微信鉴权绑定，非本公司不能使用，大部分安全问题也就没有了，就算有也不容易触发

然后有一天白帽子上报了几个漏洞，没错，不是一个，是几个，还通过漏洞搞了内网一个系统，也是从第三方采购的，但是已经废弃不使用了

大意是通过这个系统一个没有在上线后撤销的测试接口，注册了一个用户，因此通过这个可登陆的用户，访问了接口，然后发现了一个有SQL注入的接口和一个有SSRF的接口，之后通过SSRF扫内网网段，发现内网一个废弃系统的很多漏洞

下面的文章的内容都隐藏了公司和一些敏感信息

#### 漏洞说明
7月31日，白帽子通过SRC上报了4个漏洞

首先最重要的一个漏洞是一个注册接口，从我分析来看，也可以说是开发人员留下的后门了，从渗透的经验上看，是开发为了方便测试，留下了这个接口，但是在正式部署的时候没有下架，就导致的了后门

注册接口的验证token请求包

```
POST /xxx/xxx/register/token/test HTTP/1.1
Host: trip.xxxx.com
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: https://trip.xxx.com/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7
If-None-Match: "5d23f237-36c"
If-Modified-Since: Tue, 09 Jul 2019 01:47:35 GMT
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

mobile=184xxxx3380&token=123456
```

和一般的注册接口不同的是，这里接口注册的是公司信息而不是个人的，因为这个是第三方提供的服务，第三方公司会卖给很多其他公司，他们的设计中有这个需要

上面这个请求会返回一个token信息，表示通过了验证，返回token

```
POST /xxx/xxx/register/92xx40/184xxxx3380 HTTP/1.1
Host: trip.xxx.com
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: https://trip.xxx.com/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7
If-None-Match: "5d23f237-36c"
If-Modified-Since: Tue, 09 Jul 2019 01:47:35 GMT
Content-Type: application/json
Content-Length: 118

{"login":"boundaryx","fullName":"boundaryx","companyName":"boundaryx","mobile":"184xxxx3380","password":"xxxx"}
```

然后就是利用token进行注册，上面这个接口会成功注册一个公司，注册成功后就可以登陆

```
POST /xxx/token HTTP/1.1
Host: trip.xxx.com
Connection: close
Content-Length: 456
Accept: application/json, text/plain, */*
Cache-Control: no-cache
Origin: https://trip.xxx.com
Authorization: Basic QXJ0ZW1pc0FwcDpxxxxxxxxxxxxxxxxxxxRwUURkN0t3SzlJWERLOExHc2E3U09X
User-Agent: Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Mobile Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4HB4UuzTu4e2SAll
Referer: https://trip.xxx.com/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7

------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="scope"

write
------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="grant_type"

password
------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="password"

xxxx
------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="username"

boundaryx
------WebKitFormBoundary4HB4UuzTu4e2SAll--
```

然后会返回一个`access_token`，放在头部的Authorization就拥有的访问权限

攻击者有了用户权限之后，就可以访问其他接口，然后发现了一个SQL注入，一个SSRF

SQL注入没什么好讲的，SSRF可以做到完全回显，因此攻击者使用SSRF发现了内网一个系统，并直接做了渗透测试

```
# SSRF漏洞请求包
POST /xxx/xxx HTTP/1.1
Host: trip.xxx.com
Connection: close
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Mobile Safari/537.36
Referer: https://trip.xxx.com/
Accept-Encoding: gzip, deflate
Authorization: Bearer 53d25f79-8b29-47fc-b55c-b51b7b860152
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7
Content-Type: application/json
Content-Length: 168

{"url":"http://10.97.xxx.xxx/xxx.php?m=admin&c=index&a=login&dosubmit=1","params":"forward=%7B%24forward%7D&username=admin&password=admin&dosubmit=%E7%99%BB%E5%BD%95"}
```

上面这个SSRF漏洞登陆了内网系统，因为内网系统的弱口令，之后攻击者对这个系统又做了渗透，发现了很多漏洞，甚至上传了shell，这里就不详细展开了

### 0x01 第一次入侵的分析
我做入侵分析的时候，主要想搞清楚的是两点

1. 白帽子是如何发现这些漏洞的，发现漏洞的操作过程
2. 除了白帽子上报的内容外，他有没有做出格的行为

因此这次能入侵到内网，是一个大事情了，所以分析要谨慎一些，而且要有证据证明，证据一般就是日志

我做分析的时候，其他多的信息可以收集，一方面联系厂商让他们帮忙看问题，一方面自己像运维要日志进行分析

#### 如何发现这些漏洞
首先在运维没有导出日志之前，我只能自己人工从外部渗透公众号，看能否发现一样的漏洞，可以的话整个流程就比较好分析了

实际上，作为公司用户的我，用Burp Suite抓包和查看前端源码的时候没有发现白帽子上报漏洞中的任何一个接口，也就是说，不管是注册接口的后门还是SQL、SSRF，都不是这个系统对用户提供的功能

这一下就让人懵逼了，因为看白帽子上报的截图中，HTTP的头部存在`Referer`和`If-None-Match`、`If-Modified-Since`这些头部，没有浏览器加持的话，自己构造的话，不会有这些头部，如果是自己构造，那怎么发现这些接口的呢

然后还有一些令人在意的情况就是，SSRF攻击内网的时候，其实内网的没有接入SSO的废弃系统还有一些，而且按IP来看，从`10.0.0.0`暴破到白帽子发现的系统，还有很多这种类型的系统，为什么偏偏挑到了这一个

这个时候甚至是怀疑有内鬼，然后第三方厂家的回复也是含含糊糊，似乎早就知道这个漏洞，给他们一看就准备好了修复包，比较怀疑是第三方厂商人员里有内鬼

然后运维导了2天日志终于可以看了，这个时候是8月2日了

我索要的日志分成了两个部分，一个是外部这个存在SSRF的系统的日志，一个是内部被SSRF内网攻击的系统的日志，经过简单的分析，因为外网到外部系统存在一个负载均衡的转发，然后外部系统到内网系统又存在一个代理转发，原来系统日志的来源IP不可考证，所以这两个代理的日志也需要，因此一共有4份日志

导出的日志中还有另外一个严重的问题是，大部分日志只有`access.log`，也就是说POST请求的包体内容无法获取

经过初步查看最外层的代理，和外部系统的日志进行比对，攻击者一共发送了近300个请求，其中有几十个请求SQL注入接口，十几个是注册用户，两百多个SSRF接口，剩下一些前端加载和其他接口加起来都不到十几个

而这一个过程与我作为普通用户访问完全不一样，显然，攻击者并不是外网扫描到服务后，对服务做了渗透才发现这些漏洞的，更多的可能性是卖这个服务的第三方出现了问题，或者是攻击者在自己公司做了这个服务渗透，发现了这些问题，然后在公网上找其他公司的同样服务做为0day来尝试

还有一个问题是，为什么能精确访问到内网的被废弃的系统，才用了300多个请求就做到了

这个问题外网应用到内网应用的代理给了答案

![1-1](https://milkfr.github.io/assets/images/posts/2019-12-31-summary-intrusion-operation/1-1.png)

可以看到，`10.97.113.x`这个网段还是被做了暴破的，也就是内网只有这个网段和其他一些类似`admin.oa.com`等一下域名被访问了，实际上，我们是没有`admin.oa.com`这些域名的，这里肯定是攻击者猜测的

然后看被攻击的系统

![1-2](https://milkfr.github.io/assets/images/posts/2019-12-31-summary-intrusion-operation/1-2.png)

可以看出是phpcms的系统，比如错误的URL就是Controller does not exist，302会跳转到登陆界面

也许这个攻击者非常熟悉phpcms的漏洞，所以他通过网段暴破到这个系统后马上针对这个系统开始渗透，发现问题后觉得差不多了就上报SRC

梳理一下攻击流程

* 在别的地方发现了外网这家第三方公司的后门漏洞，然后发现我们公司也有，就用来对我们公司创建了一个账号，这也解释`If-Modified-Since`这些头部的时间远早于日志中最早访问这个接口的时间
* 拥有账户后，可以完全访问外网系统的接口，测试了SQL注入和SSRF两个漏洞
* 利用SSRF和攻击者自己的经验，尝试暴破了一些内网的oa域名和`10.97.113.x`这个网段
* 在`10.97.113.x`这个网段发现了一个phpcms，攻击者觉得自己熟悉，所以做起了渗透，然后又发现了一大堆漏洞，弱口令、SQL注入、文件读取、上传shell
* 攻击这觉得差不多了，就上报SRC收点钱

#### 白帽子是否有出格的行为
这里，只能比对日志进行分析

首先是注册的用户，按接口和厂商排查数据库后，确实只注册了一个公司

然后是外部系统的SQL注入，一共20几个请求，因为没有POST包，从HTTP的status code看，应该是通过bool的注入，验证是否存在SQL注入，而且次数太少，基本不能通过这个暴破数据库字段，因此看起来无害

之后是SSRF，和代理对上的数量，基本上就是暴破网段200+请求，加上对内网系统的SQL注入，文件读取，上传shell这些，因为本来就是个废弃的系统，问题不大，然后因为SSRF过来，有留下请求的SQL注入记录如下

```
111'
111
111
boundaryx
boundaryx
%' order by 1--+
%' order by 10#
a%'/**/order/**/by/**/1--+
a%'/**/order/**/by/**/1-- 
1''
1''
1' and 1 -- 
1%'-- 
1%'%23
%'and 1=1 and '%'='
%'and 1=1 and '%'='
%'and 1=2 and '%'='
%'and 1=2 and '%'='
%'and 1=a and '%'='
%'and updatexml(1,1,1) and '%'='
%'and updatexml(1,1,1) and '%'='
%'and updatexml(1,0x23,1) and '%'='
%' and (select 1) and '%'='
%' and (select 1) and '%'='
%' and 1=1 and '%'='#
%' and 1=1 and '%'='#
%'%23
%' -- 
%' /**
%'/**/%23
%'/**/and/**/1=1/**/and/**/'%'='#
%'/**/and 1=1 and '%'='
%'/**/and 1=1 and '%'='
%'/**/and/**/1=1 and '%'='
%'/**/and/**/1=1 and '%'='
%'/**/and/**/1=1/**/and '%'='
%'/**/and/**/1=1/**/and '%'='
%'/**/and/**/1=1/**/and%0A'%'='
null
null
null
null
null
null
null
null
null
null
%'/**/and/**/1=a/**/and '%'='
%'/**/and/**/1=1/**/and '%'='
%'/**/and/**/1=1/**/and '%'='
%'and updatexml(1,if(1=1,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,if((select 'sleep'),0x23,1),1) and '%'='
%'and updatexml(1,if((select 'sleep'),0x23,1),1) and '%'='
%'and updatexml(1,if(1=1,0x23,1),1) and '%'='
%'and updatexml(1,if(1=1,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1) and '%'='
null
null
111''
111''
%' order by 10--+
%' order by 1#
%'/**/order/**/by/**/1#
1
1
1'
1'and 1 -- 
1' and 1 -- '
%
%
%'and 1=2 and '%'='
%'and 1=2 and '%'='
%'and 1=sleep(5) and '%'='
%'and 1=sleep(5) and '%'='
%'and updatexml(1,if(1=1,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'#
%' #
%'--+
%' --+
%' /*
%'/**/#
%'/**/and/**/1=1/**/and/**/'%'='
%'/**/and 1=1 /and '%'='
%'/**/and/**/1=1/**/and '%'='
%'/**/and/**/1=1/**/and '%'='
%'/**/and/**/1=1/**/and/**/'%'='
%'/**/and/**/1=1/**/and+'%'='
%'/**/and/**/1=1/**/and+'%'='
null
%'/**/and/**/1=1/**/and/**/'%'='
%'/**/and/**/1=1/**/and '%'='
%'/**/and/**/1=1/**/and '%'='
'/**/and/**/1=1/**/and '%'='
'/**/and/**/1=1/**/and '%'='
%'and updatexml(1,if((select sleep(2)),0x23,1),1) and '%'='
%'and updatexml(1,if(1=sleep(10),0x23,1),1) and '%'='
%'and updatexml(1,if(1=xxx(10),0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,if(1=1,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
%'and updatexml(1,if(1=2,0x23,1),1) and '%'='
```

看来问题也不大，然后文件和系统用户等一下信息因为是被废弃了，所以被白帽子看到就看到了，上传的shell也删除，这个废弃系统的机器直接下架

因为四个系统的日志数量都对上了，基本也觉得没有什么问题了

这样看，大家就相安无事，白帽子也没做什么出格的行为，他之所以能这么快发现这些漏洞可以看作他手握这个系统0day，然后本身又比较有经验，猜网段和对phpcms渗透一气呵成，中间访问内网网段有看到不熟悉的系统都直接跳过了

### 0x02 第一次入侵后的复盘和措施
经过以上分析过后，我们选择相信了没有内鬼，是白帽子的老到经验和厂商知道漏洞但不再每家公司更新导致的问题，8月2日晚上，厂商来发布了新版本，然后说删除了用户，我们外部测试，注册接口确实不能使用了，然后内网废弃系统下架

这个事情的应急也就这样过去了，那么之后就要追责

#### 首先是渗透
我们翻出了之前对这个外部系统的渗透报告，里面没有发现白帽子上报的这些接口，和我在外部进行分析的时候一样，当时的渗透人员并不能找到这些接口，所以没有发现这个漏洞

同时，渗透报告中发现了大量这个系统存在的漏洞，也就是当时的渗透做的还可以，这几个接口确实不好找到，而且扫描器爬虫也无法发现

#### 然后是一路进来一切纵深防御全部失效
首先是有很明显的SQL注入，应用WAF没有拦截到，当然不是因为WAF能力不行，而是WAF没部署

然后是HIDS，内网系统被上传shell的时候，HIDS没有告警，要是不是白帽子上报，就不会被发现，当然也是因为HIDS未覆盖

接下来是日志审计，按理，和SQL注入一样，内网系统中存在这样的SQL注入，而且因为SSRF的关系，内网的`access.log`记录下来，没有POST缺少请求包体的问题，日志审计也没有告警，结果当然是日志审计也没有覆盖，所以分析时候导日志全靠运维，然后审批链很长，审批了两天

再然后是SQL审计，且不说有没有命中数据蜜罐，所以没有触发，明显的SQL注入语句并且成功了，但是仍然没有成功告警，原因自然也是没有覆盖这些系统

之后是防火墙，实际上外网这个系统SSRF不能访问到内网的这个废弃系统的，因为防火墙隔离了网段，但是失效了，一看防火墙策略，原来首条是`allow all`，之后的策略往后加，根本没用

最后是系统构架，因为SDL没有，只有开始项目前会有个系统构架评审，按理这种公司人员使用的系统，必须接入公司SSO，非公司人员一定不能接入，况且是企业微信公众号，但是没有按照规范的SSO接入方式，同时废弃系统直接一开始就没有接入

哈哈，就是说除了渗透，完全没有其他防御，渗透不行，其他全部不行

汇总以后的结论，就是某个区因为是OA系统的关系，所以都没加上这些防御，那就加吧，之后哪怕因为这些问题，也有地方能告警，不会被悄无声息的攻破，然后查查其他区域是否有相同的问题，一并加上

然后构架方面没有接入SSO的问题，暂时不管，因为管不了，没人力

#### 反思
这一次复盘当然是比较失败的，不是什么别的原因，就是因为问题实在太多了，所以根本不能分析到细节

比如分析日志的审批时间太长，SSO在构架时确定接入方式，完成后如何检测，废弃的系统怎么回收，内网扫描行为如何发现，现在HIDS没有这个能力，第三方厂商发现漏洞不更新等问题都没有进行讨论

光是部署WAF、HIDS、审计系统等，就需要好一段时日，而且将问题都归结为这些大方向，其实我个人觉得是很浪费这次可以被入侵的良好经验

### 0x03 权限账号留存的事件背景
上次这个事情都去快半年了，京东开了个会，反正应该是奖励白帽子的，然后有个白帽子就通过SRC跟我们说，会上有个人喝多了，说他在我们公司留存了个权限，SSRF什么的字眼

时间是在12月6日

然后就又要我来排查呗

那我就排查吧，只有留存权限和SSRF两个字眼

实际上不是有WAF、HIDS、日志审计这些，如果存在动作都应该告警，就是从来没有告过警

### 0x04 权限账号留存的分析
#### 初步排除
查就查，首选的字眼是SSRF，我把几年里所有SSRF相关的漏洞工单，全部过一边，重新从外部测试一边，然后排除法，一开始就不能进入的有很好权限管控的系统，SSRF后内网防火墙管控标好等等，排除后剩下两个

其中一个之前是没有权限管控的，但是后来加上了，测试确实不可以，而且业务做了几次迁移，域名、IP都换了，大概率不可能

最后又是上面这个问题

#### 定位问题
既然都说了是权限维持和SSRF，就先查网关记录，有没有暴破内网网段的行为，一查没有，一问，原来上次能查出来，是因为配置错误导致的，本来是不应该配置经过网关的，所以经过上次的事件后修改了规则，现在如果访问就不会在网关留下记录了

然后最开始的外网负载均衡网关，刚换了机器，所以查不到前几个月的记录了

好吧，网关日志完全不能依靠了，还不如不改原来的规则，问了原来内网的系统，确实直接把机器关了，应该不关它事了

那最后还是外网这个企业微信用的系统了，搜索了注册接口的记录，在8月我们自己复测之后就没有在访问过了

既然和权限维持有关系，就查数据库用户了，凡是不是我公司员工的账号都有问题

这一查就发现不是我们公司员工的账号实在是太多了，什么admin、test以及各种公司账号和用户账号，问第三方的公司，也不知道是怎么回事，说可能是测试用的

那只能一个个账号查过去呗，但是并没有在8月之后找到这些账号的访问记录，我甚至一度怀疑是不是拿到shell权限后删除了记录

这里有一个问题是，每个用户有actived和status两个字段，应该是标识用户禁用，主要是离职后禁用，所以对这些标识禁用的账号一开始并没有查

这里让第三方公司帮我们解释这些账号来源的过程，一直没有反应，后来还是这个系统的公司员工负责人比较热心，和我们一起看问题，有一次帮忙时，他给我看了这个系统后台

卧槽，这下真的惊呆我了，因为他给我看的后台的接口，我用Chrome开发者模式看就看到了之前找不到的SQL注入的API，然后就多找找，看到创建机构等很多接口，和之前注册公司的很相似

也就是说虽然企业微信小程序的前端不可见这些接口，但是部署的时候还是把这些接口对外了，并且和内网管理台的效果一样，这也解释了之前白帽子是怎么发现这些存在漏洞的接口，而我们渗透不能发现

这是一个重大的突破，但是并没有什么用，因为并不能解释现在的权限维持问题

后来没有突破，百无聊赖之下，就把之前SRC上报的请求包都重放一遍试试

```
POST /xxx/token HTTP/1.1
Host: trip.xxx.com
Connection: close
Content-Length: 456
Accept: application/json, text/plain, */*
Cache-Control: no-cache
Origin: https://trip.xxx.com
Authorization: Basic QXJ0ZW1pc0FwcDpxxxxxxxxxxxxxxxxxxxRwUURkN0t3SzlJWERLOExHc2E3U09X
User-Agent: Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Mobile Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4HB4UuzTu4e2SAll
Referer: https://trip.xxx.com/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7

------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="scope"

write
------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="grant_type"

password
------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="password"

xxxx
------WebKitFormBoundary4HB4UuzTu4e2SAll
Content-Disposition: form-data; name="username"

boundaryx
------WebKitFormBoundary4HB4UuzTu4e2SAll--
```

这个包竟然有正常返回。。。

多次测试之下，原来禁用用户的功能并没有用，不管是原来白帽子注册的账号还是公司离职用户的账号都是可以登陆的，全部都没有成功禁用，禁用功能就有逻辑漏洞

之后就是查这些账号有没有什么异常访问行为了

结果发现白帽子的账号在漏洞修复后的8月7日、8月13日等都进行了登录操作，还测试了之前SQL注入的接口等，请求也不是很多，因为这个系统的日志也不是把请求包都记录完整的，所以还是具体是否其他相关接口就无法判断了，看起来也都比较正常

基本认为权限维持就是指这个账号禁用失效所以可以维持注册的权限了，而白帽子因为没有更多的登录请求，所以也认为没有多余的操作了

#### 修复
到我写文章为止，问题并没有修复完，不管是上一次的各种未部署问题，还是现在新提出的外部和内网管理台相同接口禁用还是用户删除和禁用用户功能的修复都没有完成，这可怕的效率问题

### 0x05 反思安全运营
我们公司是非常重视安全运营的，不过是老板口头重视

说一些问题

* 一开始的某些区域安全防护没有部署是因为大家不了解所以不知道吗
* 上面说第一次的复盘反思是失败的，提了一些没有分析的细节问题大家都不清楚吗

看过[《切尔诺贝利》](https://www.bilibili.com/video/av59203866)，问题最开始暴露的时候，一个副总工程师说不可能，一定是某个某个小问题导致的，问题不大，之后强迫自己和下手相信了，并且在上报问题的时候，他的上级们也都这样相信了，因为宁可觉得这样是对的才最好

这里没有什么众人皆醉我独醒的感觉，其实大家都知道，但是大家都不说，喜欢把问题简化，因为大家不是老板，不敢问，尤其最底下的小兵，像我这种，往上讲还得通过自己的领导

一些区域没有安全防护是因为安全不知道公司网络的分区，常常有一种应用运维安全工程师，因为应用安全与运维是密不可分的，但是公司的网络是运维根据业务划分的，对单单的安全部门来说有隔阂，所以不知道也因为隔阂不愿意问，出事情还可以以此为理由

这也是知道问题后部署慢的原因，每一个安全防护由不同的小组完成，也没有做到每个小组的信息共享，所有的防护不能做到在申请一台主机时候默认部署好，达到默认安全，而是默认不安全，是发现问题且与自己的小组是直接责任人的时候才会卖力

然后是复盘反思是失败的，因为有些问题由哪些小组担责，内网扫描行为可能要流量监控来，这个技术好像难一些，谁来做，多一事不如少一事，所以大多数问题都可以用已有的方式，比如部署防护措施来解决，而不用更加深入思考

所以

第一个问题是大家知道，但是与自己所在组无关，别的组也这样，没必要趟这趟浑水，出事了还可以以此为由躲过一劫，大Boss不管知道还是不知道，都默许了这样

第二个问题是大家可能想到，但是多一事不如少一事，出事的理由可以用上一条覆盖，简化问题，大家就当无事发生

这样的运营显然是不合格的，本身就是有些防护程序覆盖不了的地方想办法闭环覆盖，有些没有涉及到的规则想办完闭环完善才是运营

有的安全问题被发现通过运营可以完善、覆盖、闭环，有些环境氛围的问题确实很难解决，希望以后会有所改变吧
