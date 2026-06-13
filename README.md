# udp_socket
实现UDP Socket 的自定义协议，模拟 TCP 的连接建立过程和可靠传输机制。

运行环境
1. 操作系统
   - 客户端：Windows 
   - 服务器端：Linux（VMware虚拟机）
2. Python 版本
   - Python 3.10及以上版本
3. 依赖库
   - pandas（用于 RTT 统计分析）
   安装命令：
       pip install pandas
4. 网络环境
   - Host OS与Guest OS之间网络互通

配置选项
【server.py 配置】
| 参数名     	| 默认值 	| 说明                          	  |
|--------------|---------	|----------------------------------|
| DROP_RATE    | 0.2    	| 模拟丢包率（20%）            	  |
| XOR_KEY    	| 0x5A3C    | StudentID 计算用的 XOR 密钥  	  |

【client.py 配置】
| 参数名         	| 默认值 	| 说明                          |
|----------------	|--------	|-------------------------------|
| WINDOW_SIZE     | 400    	| 发送窗口大小（字节）            |
| MIN_PKT_SIZE   	| 40     	| 最小数据包大小（字节）          |
| MAX_PKT_SIZE   	| 80     	| 最大数据包大小（字节）          |
| BASE_TIMEOUT    | 0.3    	| 初始超时时间（秒，即300ms）     |
| TOTAL_PACKETS   | 30     	| 总共发送的数据包数量            |
| XOR_KEY        	| 0x5A3C    | StudentID 计算用的 XOR 密钥    |
