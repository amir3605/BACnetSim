# ==============================================================================
# File: bacnet_gen/traffic_generator.py
# ==============================================================================
import os
import time
import random
import pandas as pd
from scapy.all import wrpcap
from .bacnet_builder import build_bacnet_read_ack_packet, build_bacnet_who_is_packet
from .attack_engine import AttackEngine

def safe_float(val, default=0.0):
    try:
        if pd.isna(val):
            return default
        return float(val)
    except (ValueError, TypeError):
        return default

class TrafficGenerator:
    def __init__(self, global_config: dict, device_configs: list):
        self.global_config = global_config
        self.device_configs = device_configs

    def generate(self, output_pcap_path: str, output_csv_path: str) -> dict:
        server_ip = self.global_config.get("server_ip", "192.168.1.100")
        server_mac = self.global_config.get("server_mac", "00:0c:29:ee:ff:00")
        server_port = int(self.global_config.get("server_port", 47808))
        max_packets = int(self.global_config.get("max_packets_per_device", 30))
        include_discovery = self.global_config.get("include_discovery", True)

        all_packets_with_ts = []
        all_ground_truth_records = []
        start_sim_time = time.time()

        for dev in self.device_configs:
            engine = AttackEngine(dev)
            csv_path = dev.get("csv_path", "")
            df = None
            if csv_path and os.path.exists(csv_path):
                try:
                    df = pd.read_csv(csv_path)
                except Exception:
                    df = None

            num_steps = max_packets
            if df is not None and len(df) > 0:
                num_steps = min(max_packets, len(df))

            current_time = start_sim_time
            invoke_counter = 1

            if include_discovery:
                who_pkt = build_bacnet_who_is_packet(
                    src_mac=dev.get("mac", "00:0c:29:11:22:33"),
                    src_ip=dev.get("ip", "192.168.1.101"),
                    port=int(dev.get("port", 47808))
                )
                who_pkt.time = current_time
                all_packets_with_ts.append((current_time, who_pkt))
                current_time += 0.05

            points = dev.get("points", [])
            valid_points = [p for p in points if str(p.get("name", "")).lower() not in ["timestamp", "device_name", "source_ip", "ip", "sourceip"]]
            if not valid_points:
                valid_points = [{"name": "Present_Value", "type": "analog_input", "instance": 0, "default_val": 20.0}]

            has_present_val = (df is not None and "Present_Value" in df.columns)

            for step in range(num_steps):
                step_delay, is_covert_step = engine.get_inter_packet_delay(step)

                if has_present_val:
                    row = df.iloc[step]
                    raw_val = safe_float(row.get("Present_Value", 0.0))
                    pt_name = str(row.get("Object_Type", "Present_Value"))
                    pt_type = "analog_input"
                    pt_inst = 0

                    sent_val, is_atk, atk_type = engine.transform_value(step, pt_name, pt_type, raw_val)
                    if is_covert_step:
                        is_atk = True
                        atk_type = "covert_channel"

                    pkt = build_bacnet_read_ack_packet(
                        src_mac=dev.get("mac", "00:0c:29:11:22:33"),
                        dst_mac=server_mac,
                        src_ip=dev.get("ip", "192.168.1.101"),
                        dst_ip=server_ip,
                        src_port=int(dev.get("port", 47808)),
                        dst_port=server_port,
                        invoke_id=invoke_counter,
                        obj_type=pt_type,
                        instance=pt_inst,
                        value=sent_val
                    )
                    pkt.time = current_time
                    all_packets_with_ts.append((current_time, pkt))

                    all_ground_truth_records.append({
                        "timestamp": round(current_time - start_sim_time, 4),
                        "source_ip": dev.get("ip", "192.168.1.101"),
                        "device_id": dev.get("device_id", 1001),
                        "device_name": dev.get("name", "Device"),
                        "point_name": pt_name,
                        "object_type": pt_type,
                        "instance": pt_inst,
                        "original_value": raw_val,
                        "sent_value": sent_val,
                        "is_attack": 1 if is_atk else 0,
                        "attack_type": atk_type
                    })
                    invoke_counter += 1

                else:
                    for pt in valid_points:
                        pt_name = pt["name"]
                        pt_type = pt.get("type", "analog_input")
                        pt_inst = int(pt.get("instance", 0))

                        raw_val = None
                        if df is not None and pt_name in df.columns:
                            raw_val = safe_float(df.iloc[step][pt_name])
                        if raw_val is None:
                            raw_val = safe_float(pt.get("default_val", 20.0))

                        sent_val, is_atk, atk_type = engine.transform_value(step, pt_name, pt_type, raw_val)
                        if is_covert_step:
                            is_atk = True
                            atk_type = "covert_channel"

                        pkt = build_bacnet_read_ack_packet(
                            src_mac=dev.get("mac", "00:0c:29:11:22:33"),
                            dst_mac=server_mac,
                            src_ip=dev.get("ip", "192.168.1.101"),
                            dst_ip=server_ip,
                            src_port=int(dev.get("port", 47808)),
                            dst_port=server_port,
                            invoke_id=invoke_counter,
                            obj_type=pt_type,
                            instance=pt_inst,
                            value=sent_val
                        )
                        pkt.time = current_time
                        all_packets_with_ts.append((current_time, pkt))

                        all_ground_truth_records.append({
                            "timestamp": round(current_time - start_sim_time, 4),
                            "source_ip": dev.get("ip", "192.168.1.101"),
                            "device_id": dev.get("device_id", 1001),
                            "device_name": dev.get("name", "Device"),
                            "point_name": pt_name,
                            "object_type": pt_type,
                            "instance": pt_inst,
                            "original_value": raw_val,
                            "sent_value": sent_val,
                            "is_attack": 1 if is_atk else 0,
                            "attack_type": atk_type
                        })
                        invoke_counter += 1

                current_time += step_delay

        all_packets_with_ts.sort(key=lambda x: x[0])
        sorted_packets = [p[1] for p in all_packets_with_ts]

        wrpcap(output_pcap_path, sorted_packets)
        df_labels = pd.DataFrame(all_ground_truth_records)
        df_labels.to_csv(output_csv_path, index=False)

        return {
            "total_packets": len(sorted_packets),
            "total_labels": len(df_labels),
            "attack_count": int(df_labels["is_attack"].sum()) if not df_labels.empty else 0,
            "pcap_path": output_pcap_path,
            "csv_path": output_csv_path
        }

def generate_bacnet_dataset(global_config: dict, device_configs: list, pcap_path: str, csv_path: str) -> dict:
    gen = TrafficGenerator(global_config, device_configs)
    return gen.generate(pcap_path, csv_path)
