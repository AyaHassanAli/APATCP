# p4runtime_controller.py
# Communicates with BMv2 switch via P4Runtime API

from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
from p4runtime_lib.simple_controller import SimpleSwitchConnection

def write_forwarding_rule(p4info_helper, sw, dst_ip, out_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={"hdr.ipv4.dstAddr": (dst_ip, 32)},
        action_name="MyIngress.forward",
        action_params={"port": out_port}
    )
    sw.WriteTableEntry(table_entry)
    print(f"Installed rule on {sw.name}: {dst_ip} -> {out_port}")

def main():
    p4info_helper = p4runtime_lib.helper.P4InfoHelper('build/apatcp.p4.p4info.txt')

    s1 = SimpleSwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=0,
        proto_dump_file='logs/s1-p4runtime-requests.txt'
    )

    s1.MasterArbitrationUpdate()
    s1.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info,
        bmv2_json_file_path='build/apatcp.json'
    )

    write_forwarding_rule(p4info_helper, s1, "10.0.0.2", 1)

    input("Press Enter to shutdown...")
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    main()
