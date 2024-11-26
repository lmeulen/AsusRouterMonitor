import sys, json
from RouterInfo import RouterInfo

param = sys.argv[1]

if __name__ == "__main__":
    ri = RouterInfo("192.168.1.1", "maxd", "Mxd.12100")
    
    # 启动时间
    if param == "uptime":
        print("Uptime    : " + str(ri.get_uptime()))
    
    # 运行时间
    if param == "uptime_secs":
        print(str(ri.get_uptime_secs()))
        
    # 内存使用百分比
    if param == "memory_usage":
        print(int(ri.get_memory_usage()['mem_used'])/int(ri.get_memory_usage()['mem_total']))
    
    # 内存已使用
    if param == "mem_used":
        print(ri.get_memory_usage()['mem_used'])
    
    # 内存空闲
    if param == "mem_free":
        print(ri.get_memory_usage()['mem_free'])
        
    # 内存总计
    if param == "mem_total":
        print(ri.get_memory_usage()['mem_total'])
    
    # cpu使用百分比
    if param == "cpu_usage":
        print((int(ri.get_cpu_usage()['cpu1_usage'])+int(ri.get_cpu_usage()['cpu2_usage'])+int(ri.get_cpu_usage()['cpu3_usage'])+int(ri.get_cpu_usage()['cpu4_usage']))/(int(ri.get_cpu_usage()['cpu1_total'])+int(ri.get_cpu_usage()['cpu2_total'])+int(ri.get_cpu_usage()['cpu3_total'])+int(ri.get_cpu_usage()['cpu4_total'])))     
    
    # cpu1使用百分比
    if param == "cpu1_usage":
        print(format(int(ri.get_cpu_usage()['cpu1_usage'])/int(ri.get_cpu_usage()['cpu1_total']), '.2f'))
    
    # cpu2使用百分比
    if param == "cpu2_usage":
        print(int(ri.get_cpu_usage()['cpu2_usage'])/int(ri.get_cpu_usage()['cpu2_total']))
    
    # cpu3使用百分比
    if param == "cpu3_usage":
        print(int(ri.get_cpu_usage()['cpu3_usage'])/int(ri.get_cpu_usage()['cpu3_total']))
    
    # cpu1使用百分比
    if param == "cpu4_usage":
        print(int(ri.get_cpu_usage()['cpu4_usage'])/int(ri.get_cpu_usage()['cpu4_total']))
        
    # 上次启动以来的发送总流量，单位MB
    if param == "traffic_total_send":
        print(float(ri.get_traffic_total()['sent'])/8.0)
        
    # 上次启动以来的接收总流量，单位MB
    if param == "traffic_total_recv":
        print(float(ri.get_traffic_total()['recv'])/8.0)
              
    # 实时发送流量，单位Mb/s
    if param == "traffic_tx":
        traffic = json.loads(ri.get_traffic())
        print(traffic['speed']['tx'])

    # 实时接收流量，单位Mb/s
    if param == "traffic_rx":
        traffic = json.loads(ri.get_traffic())
        print(traffic['speed']['rx'])
               
    # wan口状态    
    if param == "status_wan":
        print(ri.get_status_wan()['status'])
        
    # wan口ip地址
    if param == "wan_ip":
        print(ri.get_status_wan()['ipaddr'])
        
    # wan口联网状态    
    if param == "is_wan_online":
        is_wan_online = ri.is_wan_online()
        if is_wan_online == True:
            print(1)
        if is_wan_online == False:
            print(0)
        
    # cpu温度  
    if param == "cpu_temperature":
        print(ri.get_cpu_temperature()['cpu_temperature']) 
        
