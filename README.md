# MPTCP
借助MPTCP项目已经搭建好的环境，修改了pcap4j库里读pcap包的代码，实现了读取相关pcap包并且计算所需要的几项特征的功能。
在使用时要主要导入MPTCP/lib作为library，并且应用于MPTCP模块而不是mptcp模块，然后在外部包导入的slf4j的api和sample的jar包版本一定要一致
