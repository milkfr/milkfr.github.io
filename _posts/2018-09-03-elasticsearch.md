---
title: Elasticsearch
description: Elasticsearch
categories:
 - ES Stack
tags:
 - ES Stack
 - Elasticsearch
 - 技术栈
---

### Elasticsearch
#### Elasticsearch配置说明
主要配置文件
* elasticsearch.yml es相关配
    * cluster.name 集群名称，以此作为是否同一集群的判断条件
    * node.name 节点名称，以此作为集群中不同节点的区分条件
    * network.host/http.port 网络地址和端口，用于http和transport服务使用
    * path.data 数据存储地址
    * path.log 日志存储地址
* jvm.options jvm的相关参数
* log4j2.properties 日志相关配置

Development和Production模式说明
* 以transport的地址是否绑定在localhost为判断标准network.host
* Development模式下在启动时会以warning的方式提示配置检查异常
* Production模式下在启动时会以error的方式提示配置检查异常并退出

参数修改可以使用`bin/elasticsearch -Ehttp.port=19200`的方式

#### 本地快速启动集群
```
bin/elasticsearch
bin/elasticsearch -Ehttp.port=8200 -Epath.data=node2
bin/elasticsearch -Ehttp.port=7200 -Epath.data=node3

127.0.0.1:8200/_cat/nodes?v  # 查看是否已经组成集群，v参数显示详细信息
127.0.0.1:8200/_cluster/status  # 显示集群详细信息
```

#### Elasticsearch常用术语
* Document 数据单元，对应数据库的一行数据，实际是Json Object，每个文档有唯一的id标识
* Index 索引，由具有相同字段的文档列表组成，对应数据库表（6.0后不允许建多个type，不再等同于数据库），每个索引都有自己的mapping定义
* Type 索引中的数据类型，以后版本中会删去
* Field 字段，文档的属性
* Query DSL 查询语法
* Node 运行实例，集群构成单元
* Cluster 由一个或多个节点组成，对外提供服务

#### Elasticsearch CRUD
* Create 创建文档
```
# Reqeust
POST /accounts/person/1
{
    "name": "John",
    "lastname": "Doe",
    "job_description": "Systems administrator and Linux specialit"
}
```

* 批量创建文档API
```
# Request, index和create的区别是，文档存在时，index不会报错，会覆盖，create会报错
POST _bulk
{"index": {"_index": "test_index", "_type": "doc", "_id": "3"}}
{"username": "alfred", "age": 10}
{"delete": {"_index": "test_index", "_type": "doc", "_id": "1"}}
{"update": {"_id": "2", "_index": "test_index", "_type": "doc"}}
{"doc": {"age": "20"}}
```

* Read 读取文档
```
# Request
GET /accounts/person/1
```

* 批量查询
```
GET /_mget
{"docs": [{"_index": "test_index", "_type": "doc", "_id": "1"},{"_index": "test_index", "_type": "doc", "_id": "2"}]}
```

* Update 更新文档
```
# Request
POST /accounts/person/1/_update
{
    "doc": {
        "job_description": "Systems administrator and Linux specialist"
    }
}
```

* Delete 删除文档
```
# Request
DELETE /accounts/person/1
```

#### Elasticsearch查询简介
* Query String
```
GET /accounts/person/_search?q=john
```

* Query DSL
```
GET /accounts/person/_search
{
    "query": {
        "match": {
            "name": "john"
        }
    }
}
```

#### Elasticsearch索引简介
* 正排索引（文档ID到文档内容、单词的关联关系）
* 倒排索引（单词到文档ID到关联关系）
    * 通过倒排索引查询包含某个单词对应的文档ID有1和3
    * 通过正排索引查询1和3的完整内容
    * 返回结果
* 倒排索引组成
    * 单词词典（Term Dictionary）
        * 记录所有文档的单词，一般都比较大
        * 记录单词到倒排列表的关联信息
        * 一般用B+ Tree实现
    * 倒排列表（Posting List）
        * 记录单词对应的文档集合
        * 文档ID、单词频率（出现次数，用于相关性算分），位置（用于词语搜索Phrase Query），偏移（开始结束位置，用于高亮显示）
* 分词器（Analyzer）模块划分
    * Character Filters
        * 针对原始文本进行处理，比如去除HTML标签符号
    * Tokenizer
        * 将原始问题按照一定规则切分为单词
    * Token Filters
        * 针对tokenizer处理的单词进行再加工，比如转小写、删除或新增等处理
    * analyze API（es提供等测试分词效果等API）
        * 可以直接指定analyze进行测试（测试分词器效果）
        * 可以直接指定索引中的字段进行测试（索引查询输出和期望不一致，个例测试）
        * 可以自定义分词器进行测试（定制组件的调试）
