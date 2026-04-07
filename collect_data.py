import csv
import time
import os
import asyncio
from datetime import datetime

# Import tường minh (explicit) thay vì dùng dấu * để đảm bảo không bao giờ lỗi 'not defined'
from pysnmp.hlapi.asyncio import (
    SnmpEngine, get_cmd, CommunityData, UdpTransportTarget, 
    ContextData, ObjectType, ObjectIdentity
)

# --- Configuration ---
COMMUNITY = 'public'
CSV_FILENAME = 'normal_snmp.csv'
INTERVAL = 15

# Khởi tạo MỘT engine duy nhất để dùng chung cho tất cả các request
snmp_engine = SnmpEngine()

# Define all devices to poll: name -> IP
DEVICES = {
    'device1': '172.16.0.80',
    'device2': '172.16.0.1',
    'device3': '10.0.0.1',
    'device4': '192.168.10.10',
    'device5': '192.168.20.10',
}

# Define interface names and their SNMP ifIndex per device.
DEVICE_INTERFACES = {
    'device1': {'enp0s3': 2, 'enp0s8': 3, 'enp0s9': 4, 'enp0s10': 5},
    'device2': {'enp0s3': 2, 'enp0s8': 3, 'enp0s9': 4, 'enp0s10': 5},
    'device3': {'enp0s3': 2, 'enp0s8': 3, 'enp0s9': 4, 'enp0s10': 5},
    'device4': {'enp0s3': 2, 'enp0s8': 3, 'enp0s9': 4, 'enp0s10': 5},
    'device5': {'enp0s3': 2, 'enp0s8': 3, 'enp0s9': 4, 'enp0s10': 5},
}

# --- Global OIDs (same for all devices, no interface index needed) ---
GLOBAL_OIDS = {
    'tcpActiveOpens':      '1.3.6.1.2.1.6.5.0',
    'tcpCurrEstab':        '1.3.6.1.2.1.6.9.0',
    'tcpEstabResets':      '1.3.6.1.2.1.6.8.0',
    'tcpInSegs':           '1.3.6.1.2.1.6.10.0',
    'tcpOutRsts':          '1.3.6.1.2.1.6.15.0',
    'tcpOutSegs':          '1.3.6.1.2.1.6.11.0',
    'tcpPassiveOpens':     '1.3.6.1.2.1.6.6.0',
    'tcpRetransSegs':      '1.3.6.1.2.1.6.12.0',
    'udpInDatagrams':      '1.3.6.1.2.1.7.1.0',
    'udpInErrors':         '1.3.6.1.2.1.7.3.0',
    'udpNoPorts':          '1.3.6.1.2.1.7.2.0',
    'udpOutDatagrams':     '1.3.6.1.2.1.7.4.0',
    'ipForwDatagrams':     '1.3.6.1.2.1.4.6.0',
    'ipInAddrErrors':      '1.3.6.1.2.1.4.5.0',
    'ipInDelivers':        '1.3.6.1.2.1.4.9.0',
    'ipInDiscards':        '1.3.6.1.2.1.4.8.0',
    'ipInReceives':        '1.3.6.1.2.1.4.3.0',
    'ipOutNoRoutes':       '1.3.6.1.2.1.4.12.0',
    'ipOutDiscards':       '1.3.6.1.2.1.4.11.0',
    'ipOutRequests':       '1.3.6.1.2.1.4.10.0',
    'icmpInDestUnreachs':  '1.3.6.1.2.1.5.3.0',
    'icmpInEchos':         '1.3.6.1.2.1.5.8.0',
    'icmpInMsgs':          '1.3.6.1.2.1.5.1.0',
    'icmpOutDestUnreachs': '1.3.6.1.2.1.5.16.0',
    'icmpOutEchoReps':     '1.3.6.1.2.1.5.22.0',
    'icmpOutMsgs':         '1.3.6.1.2.1.5.14.0',
}

# --- Per-interface OID templates ---
INTERFACE_OID_TEMPLATES = {
    'ifInOctets':     '1.3.6.1.2.1.2.2.1.10',
    'ifInUcastPkts':  '1.3.6.1.2.1.2.2.1.11',
    'ifInNUcastPkts': '1.3.6.1.2.1.2.2.1.12',
    'ifInDiscards':   '1.3.6.1.2.1.2.2.1.13',
    'ifOutOctets':    '1.3.6.1.2.1.2.2.1.16',
    'ifOutUcastPkts': '1.3.6.1.2.1.2.2.1.17',
    'ifOutNUcastPkts':'1.3.6.1.2.1.2.2.1.18',
    'ifOutDiscards':  '1.3.6.1.2.1.2.2.1.19',
}

def build_oids_for_device(device_name):
    oids = dict(GLOBAL_OIDS)
    interfaces = DEVICE_INTERFACES.get(device_name, {})
    for iface_name, if_index in interfaces.items():
        for counter_name, oid_base in INTERFACE_OID_TEMPLATES.items():
            col_name = f"{counter_name}_{iface_name}"
            oids[col_name] = f"{oid_base}.{if_index}"
    return oids

async def get_snmp_value(ip, community, oid):
    try:
        # Pysnmp v6 bắt buộc tạo Transport Target thông qua .create()
        target = await UdpTransportTarget.create((ip, 161), timeout=2.0, retries=2)

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            CommunityData(community),
            target, # Truyền biến target đã tạo ở trên vào đây
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        if errorIndication:
            #print(f"[{ip}] Lỗi kết nối/Timeout với OID {oid}: {errorIndication}")
            return 0
        elif errorStatus:
            #print(f"[{ip}] Lỗi SNMP Agent với OID {oid}: {errorStatus.prettyPrint()}")
            return 0
        else:
            val = varBinds[0][1].prettyPrint()
            if "No Such Instance" in val or "No Such Object" in val:
                return 0
            return val if val != '' else 0

    except Exception as e:
        #print(f"[{ip}] Python Exception với OID {oid}: {str(e)}")
        return 0

def append_data(filename, data_dict, headers):
    file_exists = os.path.isfile(filename)
    with open(filename, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data_dict)

async def poll_all_oids(ip, community, oids_dict):
    names = list(oids_dict.keys())
    coros = [get_snmp_value(ip, community, oids_dict[name]) for name in names]
    values = await asyncio.gather(*coros)
    return dict(zip(names, values))

async def poll_device(device_name, device_ip, oids_dict, timestamp):
    row_data = {'Timestamp': timestamp, 'Device': device_name, 'IP': device_ip}
    oid_results = await poll_all_oids(device_ip, COMMUNITY, oids_dict)
    row_data.update(oid_results)
    return row_data

async def main_loop():
    device_configs = {}
    for device_name, device_ip in DEVICES.items():
        oids = build_oids_for_device(device_name)
        device_configs[device_name] = {
            'ip': device_ip,
            'oids': oids,
        }

    all_oid_columns = []
    seen = set()
    for cfg in device_configs.values():
        for col_name in cfg['oids'].keys():
            if col_name not in seen:
                all_oid_columns.append(col_name)
                seen.add(col_name)

    csv_headers = ['Timestamp', 'Device', 'IP'] + all_oid_columns
    total_oids = sum(len(cfg['oids']) for cfg in device_configs.values())

    print(f"--- Bắt đầu thu thập SNMP ---")
    print(f"Số lượng thiết bị: {len(DEVICES)} ({', '.join(DEVICES.keys())})")
    print(f"Tổng số OIDs cần lấy mỗi chu kỳ: {total_oids}")
    for name, cfg in device_configs.items():
        ifaces = list(DEVICE_INTERFACES.get(name, {}).keys())
        print(f"  {name} ({cfg['ip']}): {len(cfg['oids'])} OIDs, interfaces: {', '.join(ifaces) if ifaces else 'none'}")
    print(f"Lưu dữ liệu tại: {CSV_FILENAME}")
    print(f"Chu kỳ lấy mẫu: {INTERVAL} giây")
    print("Nhấn Ctrl+C để dừng script.\n")

    try:
        while True:
            start_time = time.time()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            print(f"[{timestamp}] Đang lấy dữ liệu từ {len(DEVICES)} thiết bị...", end=" ", flush=True)

            tasks = [
                poll_device(device_name, cfg['ip'], cfg['oids'], timestamp)
                for device_name, cfg in device_configs.items()
            ]
            results = await asyncio.gather(*tasks)

            for row_data in results:
                append_data(CSV_FILENAME, row_data, csv_headers)

            device_names = [r['Device'] for r in results]
            print(f"Xong ({', '.join(device_names)}).")

            elapsed = time.time() - start_time
            time_to_wait = max(0, INTERVAL - elapsed)
            await asyncio.sleep(time_to_wait)

    except KeyboardInterrupt:
        print("\nScript đã được dừng bởi người dùng.")

if __name__ == "__main__":
    asyncio.run(main_loop())
