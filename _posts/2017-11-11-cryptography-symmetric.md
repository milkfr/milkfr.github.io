---
title: 密码学家的工具箱——对称密码
description: 文章主要根据《图解密码技术》，经过自己理解筛选排列，大学学了8门密码学课程，不如一本好书讲得清楚，记录供以后回顾
categories:
 - 密码学
tags:
 - 密码学
---

### 0x00 一次性密码本
一次性密码本绝对无法破译，了解有这个东西即可，不用太认真了解这个

一次性密码本是一种非常简单的密码，它的原理是"将明文与一串随机的比特序列进行XOR计算"

这串随机的比特序列就是密钥

加密是明文XOR密钥，解密是密文XOR密钥，是最简单的对称密码

一次性密码本无法破译的原因是无法判断解密出的结果是否是正确明文，即使有算力无穷大的计算机，在一瞬间遍历任意大小的密钥空间，也无法确定那一个明文是正确的

香农于1949年通过数学方法证明一次性密码本是无条件安全的，在理论上是无法破译的

一次性密码本的不实用是因为密钥的配送、保存、重用和同步、生成都太过麻烦

一个比较重要的小知识点：一次性密码本的密钥无法进行压缩，因为压缩原理比如大学数据结构和算法学的哈夫曼树压缩都是找出数据中出现的冗余重复序列，并将他们替换成较短的数据，然而一次性密码本所使用的密钥是随机的，其中不包含任何冗余的重复序列，反过来说，如果一个比特序列能够被压缩，就说明它不是一个随机的比特序列

### 0x01 DES(Data Encryption Standard)
#### 概述
DES是一种将64比特明文加密成64比特的密文的对称密码算法，密钥长度56比特，尽管从规格上来讲，DES的密钥长度是64比特，但由于每隔7比特会设置一个用于错误检查的比特，所以实质上密钥长度是56比特

DES是以64比特的明文为一个单位来进行加密的，这个64比特的单位称为分组，一般来说，以分组为单位进行处理的密码算法称为分组密码，DES每次只能加密1组数据，如果加密的明文比较长，就需要对DES加密进行迭代，迭代的方式称为模式，本文接下去就说明

#### 加解密流程
DES的基本结构是由Horst Feistel设计的，因此也称为Feistel网络，DES是一种16轮循环的Feistel网络

Feistel网络中，加密的各个步骤称为轮（round），一轮加密和解密计算如下图所示

![1-1](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/1-1.png)

一轮加密计算的具体步骤

* 子密钥是指本轮加密所使用的密钥
* 将输入的数据分成左右两部分
* 将输入的右侧直接发送到输出的右侧
* 将输入的右侧发送到轮函数
* 轮函数根据右侧数据和子密钥，计算出一串看上去是随机的比特序列
* 将上一步得到的比特序列与左侧数据进行XOR运算，并将结果作为加密后的左侧

但是这样一轮，右侧根本没有被加密，因此我们需要用不同的子密钥对一轮的处理重复若干次，并在两轮处理之间将左侧和右侧数据对调

解密如上图的下半部分，右侧数据和子密钥、轮函数计算结果相同，密文与相同计算结果XOR就是明文了，多轮计算就重复多次

![1-2](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/1-2.png)

![1-3](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/1-3.png)

#### Feistel网络的特性
* 轮数可以任意增加
* 加密是无论如何使用任何函数作为轮函数都可以正确解密，轮函数无需考虑解密的问题，可以被设计得任意复杂
* 加密和解密可以使用完全相同的结构来实现，硬件和软件的实现更简单

所以，无论任何轮数，任何轮函数，Feistel网络都可以用相同的结构实现加密和解密，且加密的结果必定能够正确解密，所以Feistel网络的本质就是从加密算法中提取出"密码的本质部分"并将其封装成一个轮函数

### 0x02 三重DES
#### 概述
DES已经可以在现实的时间内被暴力破解，因此我们需要一种用来替代DES的分组密码，也就是三重DES

三重DES是为了增加DES的强度，将DES重复三次所得到的一种密码算法

#### 加解密流程
明文经过三次DES处理才能变成最后的密文，由于DES的密钥的长度实质上是56比特，因此三重DES的密钥长度就是56*3=168比特

加密过程如下图所示

![2-1](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/2-1.png)

从上图可以发现，三重DES并不是进行三次DES加密，而是加密->解密->加密的过程，目的是为了让三重DES能够兼容普通的DES

### 0x03 AES
AES是取代前任标准（DES）称为新标准的一种对称密码算法，是通过对世界公开选拔，通过竞争来实现标准化的方式，选出来名为Rijndael的对称密码算法

AES的规格中，分组长度固定为128比特，密钥长度只用128、192、256比特三种

#### 加解密流程
DES使用Feistel网络作为基本结构，而Rijndael没有使用Feistel网络，使用SPN结构，也是多个轮构成，每一轮分成SubBytes、ShiftRows、MixColumns和AddRoundKey四个步骤

首先是SubBytes步骤

Rijndael的输入分组为128比特，也就是16字节，首先，需要逐个字节对16字节的输入数据进行SubBytes处理，就是以每个字节的值（0～255的任意值）为索引，从一张拥有256个值的替换表（S-Box）中查找出对应值的处理，可以理解为按固定的密码本进行替换

![3-1](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/3-1.png)

之后是ShiftRows步骤

这一步将以4字节为单位的行，按照一定规则向左平移，且每一行平移的字节数是不同的

![3-2](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/3-2.png)

之后是MixColumns步骤

这一步是对一列4字节的值进行矩阵运算，将其变成另外一个4字节值

![3-3](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/3-3.png)

最后是AddRoundKey处理

这一步将MixColumns的输出与轮密钥进行XOR

![3-4](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/3-4.png)

这样，Rijndael的一轮就结束了，实际上在Rijndael中要进行10～14轮计算

解密只需要逆着4步进行就可以

![3-5](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/3-5.png)

通过上面的结构我们可以发现所有比特在一轮中都会被加密，每一轮都只加密一半输入的比特的Feistel网络相比，这种方式优势在于加密所需要的轮数更少，此外，这种方式还有一个优势，即SubBytes、ShiftRows和MixColumns可以分字节、行和列为单位进行并行计算

### 0x04 分组密码的模式
#### 分组密码和流密码
密码算法可以分为分组密码和流密码两种

分组密码每次只能处理特定长度的一块数据的一类密码算法，这里一块就是一个分组，一个分组的比特数量称为分组长度

DES和三重DES的分组长度是64比特，AES的分组长度是128比特

流密码是对数据流进行连续处理的一类密码算法，一般以1比特、8比特或者32比特为单位进行加解密

分组密码处理完一个分组就结束了，因此不需要通过内部状态来记录加密的进度，相对的，流密码是对一串数据流进行连续处理，因此需要保持内部状态

对称密码除了一次性密码本是流密码，其他大多数都是分组密码

对分组进行迭代的方式称为分组密码的模式

#### ECB模式
ECB模式的全称是Electronic CodeBook模式，将明文分组加密之后的结果直接称为密文分组，称为电子密码本模式

![4-1](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-1.png)

ECB模式中，每个明文分组都各自独立进行加密和解密，是很大的弱点

一个是改变密文顺序就改变了明文顺序，二是相同明文会得到相同密文，可以作为破译线索

#### CBC模式
CBC模式的全称是Cipher Block Chaining模式（密文分组链接模式），CBC模式中，明文分组先与前一个密文分组进行XOR运算，然后进行加密

![4-2](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-2.png)

ECB模式只进行了加密，而CBC模式则在加密之前进行了一次XOR

初始化向量一般每次加密随机产生一个不同的比特序列作为初始化向量，如果相同，加密相同明文的结果会一样

CBC模式的特点就是无法单独对中间一个分组进行加密，如果有一个分组数据损坏，最多影响两个分组

![4-3](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-3.png)

CBC模式的弱点有比特反转攻击

![4-4](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-4.png)

填充提示攻击

以及初始化向量IV不使用不可预测随机数导致的各种问题

#### CFB模式
CFB模式的全称是Cipher FeedBack模式（密文反馈模式），在CFB模式中，前一个密文分组会被送到密码算法的输入端，所谓反馈，就是指返回输入端的意思

![4-5](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-5.png)

CFB模式中由密码算法所生成的比特序列称为密钥流，在CFB模式中，密码算法就相当于用来生成密钥流的伪随机数生成器，而初始化向量就相当于伪随机数生成器的种子，因此可以将CFB模式看作是一种使用分组密码来实现流密码的方式

CFB模式可以实施重放攻击

![4-6](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-6.png)

#### OFB模式
OFB模式的全称是Output-Feedback模式（输出反馈模式），在OFB模式中，密码算法的输出会反馈到密码算法的输入中

![4-7](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-7.png)

![4-8](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-8.png)

#### CTR模式
CTR模式全称是CounTeR模式（计数器模式），CTR模式是一种通过将逐次累加的计算器进行加密来生成密钥流的流密码

![4-9](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-9.png)

计数器模式初始值也是和IV差不多的nonce，需要每次不同

#### 区别比较
![4-10](https://milkfr.github.io/assets/images/posts/2017-11-11-cryptography-symmetric/4-10.png)
