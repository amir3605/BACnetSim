# ==============================================================================
# File: bacnet_gen/bacnet_builder.py
# ==============================================================================
import struct
from scapy.all import Ether, IP, UDP, Raw

BACNET_OBJECT_TYPES = {
    "analog_input": 0, "analog-input": 0, "analoginput": 0,
    "analog_output": 1, "analog-output": 1, "analogoutput": 1,
    "analog_value": 2, "analog-value": 2, "analogvalue": 2,
    "binary_input": 3, "binary-input": 3, "binaryinput": 3,
    "binary_output": 4, "binary-output": 4, "binaryoutput": 4,
    "binary_value": 5, "binary-value": 5, "binaryvalue": 5
}

def encode_object_id(obj_type_str: str, instance: int) -> bytes:
    type_id = BACNET_OBJECT_TYPES.get(str(obj_type_str).lower().replace(" ", "_"), 0)
    val = (type_id << 22) | (int(instance) & 0x3FFFFF)
    return struct.pack("!I", val)

def build_bacnet_who_is_packet(src_mac: str, src_ip: str, port: int = 47808):
    bvlc = b"\x81\x0b\x00\x10"
    npdu = b"\x01\x20\xff\xff\x00\xff"
    apdu = b"\x10\x08"
    return Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=src_ip, dst="255.255.255.255") / UDP(sport=port, dport=port) / Raw(load=bvlc + npdu + apdu)

def build_bacnet_read_ack_packet(
    src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
    src_port: int = 47808, dst_port: int = 47808,
    invoke_id: int = 1, obj_type: str = "analog_input",
    instance: int = 0, value = 0.0
):
    try:
        clean_val = float(value)
    except (ValueError, TypeError):
        clean_val = 0.0

    npdu = b"\x01\x00"
    obj_bytes = encode_object_id(obj_type, instance)
    apdu_header = struct.pack("!BBB", 0x30, invoke_id & 0xFF, 0x0c) + b"\x0c" + obj_bytes
    prop_bytes = b"\x19\x55"
    open_tag = b"\x3e"

    if "binary" in str(obj_type).lower():
        val_int = 1 if int(round(clean_val)) > 0 else 0
        val_bytes = struct.pack("!BB", 0x91, val_int)
    else:
        val_bytes = b"\x44" + struct.pack("!f", clean_val)

    close_tag = b"\x3f"
    apdu = apdu_header + prop_bytes + open_tag + val_bytes + close_tag
    bvlc_len = 4 + len(npdu) + len(apdu)
    bvlc = struct.pack("!BBH", 0x81, 0x0a, bvlc_len)

    return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=bvlc + npdu + apdu)
