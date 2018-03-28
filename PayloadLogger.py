#!/usr/bin/env python
# -*- coding:utf-8 -*-


"""
基于HTTP的Burpsuite、Sqlmap等的Payload收集器
作者:陈然
版本：V1.0.1
联系：WeChat-Number -> cr1914518025
"""


#脚本信息配置:
_author  = "陈然"
_nicky   = "挖洞的土拨鼠"
_version = "v1.0.1"
_version_string = """\033[0;32m
            基于HTTP的Burpsuite、Sqlmap等的Payload收集器
            作者:陈然
            版本：V1.0.1
            联系：WeChat-Number -> cr1914518025
            操作系统：支持Linux、Unix、MacOS X
\033[0m"""

#引入依赖的库文见、包
import sys
import time
import pcap
import dpkt
import urllib
import logging
import datetime
from threading import Thread
from optparse import OptionParser


#配置全局设置
reload(sys)
sys.setdefaultencoding("utf-8")
logging.basicConfig(filename="./burpsuite_payload_logger.error.log",level=logging.INFO,filemode='a',format='%(asctime)s-%(levelname)s:%(message)s')


#定义数据报文栈结构
class packet_queue(object):
    """存储报文的数据结构"""
    def __init__(self):
        """创建数据报文结构队列"""
        logging.info("创建报文存储结构")
        self.size = 0#初始化队列数目
        self.packet_list = []#初始化队列
    def push(self,packet):
        """向队列中追加一个数据报文"""
        logging.info("添加一个报文信息")
        self.packet_list.append(packet)
        self.size += 1#队列数据报文+1
    def pop(self):
        """当队列中的报文数目多于0个的事后，获取队列中的一个数据报文"""
        logging.info("获取一个报文信息")
        if self.size != 0:
            ret = self.packet_list[0]
            self.packet_list.remove(self.packet_list[0])
            self.size -= 1
            return ret
        else:
            return None
    def isempty(self):
        """返回队列是否为空"""
        if self.size == 0:
            return True
        else:
            return False


#定义Payload记录文件类
class PayloadFile(object):
    def __init__(self):
        self.file = "./PayloadLogger.txt"
    def logit(self,string):
        with open(self.file,'a') as fw:
            logging.info("记录一个Payload报文数据!")
            now = str(datetime.datetime.now())
            fw.write("^"*150+"\n"+now+"\n"+string+"^"*150+"\n\n\n\n")

#定义全局变量
PacketQueue = packet_queue()#报文存储队列
PayloadLogging = PayloadFile()


#定义全局函数
def http_request_analyst(string):
    """解HTTP请求报文"""
    logging.info("分析报文请求")
    global PayloadLogging
    PayloadLogging.logit(string)
    string = string[0:-1]
    method = string.split(" ")[0]
    print "\n"
    print "\033[0;32m^\033[0m"*120
    print "\033[1;32;40mMethod:%s\033[0m"%str(method)
    path = string.split(" ")[1]
    print "\033[1;32;40mPath:%s\033[0m"%str(urllib.unquote(path))
    protover = string.split(" ")[2].split("\r\n")[0]
    print "\033[1;32;40mProtocol Version:%s\033[0m"%str(protover)
    string = string.replace("HTTP/1.","\\r\\n\\r\\n\\r\\n")
    headers = string.split("\\r\\n\\r\\n\\r\\n")[-1].split("\r\n\r")[0]
    for header in headers.split("\r\n")[1:]:
        header = header.split(":")
        try:
            hstr = "%s:%s"%(str(header[0]),str(header[1])) if header[0] not in ["Referer"] else "%s:%s:%s"%(str(header[0]),str(header[1]),str(header[2]))
        except Exception,reason:
            logging.error(reason)
            continue
        print "\033[1;32;40m%s\033[0m"%hstr
    print "\033[1;32;40mData:%s\033[0m"%string.split("\\r\\n\\r\\n\\r\\n")[-1].split("\r\n\r")[-1].replace("\n","")
    print "\033[0;32m^\033[0m"*120
    print "\n"


#定义Burpsuite报文获取类
class Packet_Sniffer_Filter(Thread):
    """嗅探并过滤报文"""
    def __init__(self,destinationip,siteport,iterfacename):
        """创建报文嗅探器"""
        logging.info("创建嗅探器")
        Thread.__init__(self,name="Packet_Sniffer_Filter")#调用父类构造函数
        self.dip = destinationip#过滤器目的地址
        self.port = siteport#站点的HTTP服务端口
        self.name = iterfacename#本机的嗅探网卡名称
        self.sniffer = pcap.pcap(name=self.name)#设置嗅探器嗅探指定网卡
        self.sniffer.setfilter("tcp port %s"%self.port)#初步过滤
    def run(self):
        """过滤IP地址"""
        logging.info("嗅探器线程开始运行")
        global PacketQueue
        while True:
            for packet_time,packet_data in self.sniffer:
                packet = dpkt.ethernet.Ethernet(packet_data)#使用dpkt解pcap格式报文
                dip = tuple(map(ord,list(packet.data.dst)))#获取目的IP地址
                dip = str(str(dip[0])+"."+str(dip[1])+"."+str(dip[2])+"."+str(dip[3]))
                logging.info("开始过滤站点")
                if dip == self.dip:#过滤目的IP地址
                    logging.info("压入一个站点报文")
                    PacketQueue.push(packet.data.data.data)#加入待分析队列
                else:
                    logging.info("过滤一个站点报文")
                    continue


#定义报文分析写文件类
class Packet_Analyst(Thread):
    """报文分析器"""
    def __init__(self):
        """创建报文分析器"""
        logging.info("创建解析器")
        Thread.__init__(self,name="Packet_Analyst")
    def run(self):
        """分析队列中的报文"""
        logging.info("解析器线程开始运行")
        global PacketQueue
        while True:
            while not PacketQueue.isempty():
                packet = PacketQueue.pop()
                logging.info("获取一个站点报文")
                if packet == '':
                    continue
                try:
                    logging.info("解析一个站定报文")
                    http_request_analyst(packet)
                except Exception,reason:
                    logging.error(reason)
                    continue
            time.sleep(1)


if __name__ == "__main__":
    logging.info("程序启动")
    parser = OptionParser()
    parser.add_option("-t","--dstip",dest="target",help="Target Site IP Addresses!")
    parser.add_option("-p","--port",dest="port",help="Target Site Port!")
    parser.add_option("-i","--ifname",dest="name",help="Interface Name!")
    parser.add_option("-v","--version",dest="version",action="store_true",help="Show Version!")
    parser.add_option("-d","--docs",dest="docs",action="store_true",help="Show Documents!")
    parser.add_option("-r","--requirments",dest="reqr",action="store_true",help="Show Requriments!")
    (options, arges) = parser.parse_args()
    if options.version:
        print _version_string
        exit(0)
    if options.docs:
        print """\033[0;32m
            使用手册--使用于V1.0.1版本
            [1] python PayloadLogger.py -t 192.168.1.1 -p 80 -i eth1 &
        \033[0"""
        exit(0)
    if options.reqr:
        print """\033[0;32m
            [+] sudo pip install pypcap
            [+] sudo pip install dpkt
        \033[0"""
        exit(0)
    if options.target in ["",None]:
        logging.info("程序缺乏目标站点地址参数，退出运行!")
        print "\033[0;31m[-] 请指定目标站点!\033[0m"
        exit(0)
    if options.port in ["",None]:
        logging.info("程序缺乏目标站点端口参数，默认端口80!")
        print "\033[0;32m[-] 目标站点获取端口失败，将使用默认端口80\033[0"
        options.port = "80"
    else:
        try:
            options.port = int(options.port)
            options.port = str(options.port)
        except Exception:
            logging.info("程序获取目标站点端口参数错误，默认端口80!")
            print "\033[0;32m[-] 目标站点获取端口失败，将使用默认端口80\033[0"
            options.port = "80"
    if options.name in ["",None]:
        logging.info("程序缺乏网卡参数，退出运行!")
        print "\033[0;31m[-] 请指定网卡\033[0m"
        exit(0)
    logging.info("程序初始化")
    PacketSniffer = Packet_Sniffer_Filter(options.target,options.port,options.name)
    PacketSniffer.start()
    PacketAnalyst = Packet_Analyst()
    PacketAnalyst.start()
    PacketSniffer.join()
    PacketAnalyst.join()

# packet_time  => packet receive time
# packet_data  => ethernet level data
