# pysnmp 6.x uses asyncio API
import asyncio
from pysnmp.hlapi.asyncio import *

TARGET_IP = '192.168.56.20'  
COMMUNITY = 'public'         

async def test_snmp():
    print(f"Attempting to contact {TARGET_IP}...")
    
    try:
        transport_target = await UdpTransportTarget.create((TARGET_IP, 161), timeout=2.0, retries=2)
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            SnmpEngine(),
            CommunityData(COMMUNITY),
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'))  # sysUpTime
        )

        # Check results
        if errorIndication:
            print(f"FAILED (Connection): {errorIndication}")
            print("  -> Check if IP is correct.")
            print("  -> Check if device is reachable (ping 192.168.56.20).")
            print("  -> Check if UDP port 161 is open on the target.")
            
        elif errorStatus:
            print(f"FAILED (SNMP Error): {errorStatus.prettyPrint()}")
            print("  -> The device responded but didn't like the request.")
            
        else:
            result = varBinds[0][1].prettyPrint()
            print(f"SUCCESS! Connected.")
            print(f"  -> System Uptime: {result}")
            print("  -> Your main script should work now.")

    except Exception as e:
        print(f"CRITICAL PYTHON ERROR: {e}")
        import traceback
        traceback.print_exc()

asyncio.run(test_snmp())