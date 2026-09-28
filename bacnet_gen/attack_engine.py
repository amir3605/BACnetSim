# ==============================================================================
# File: bacnet_gen/attack_engine.py
# Description: Attack Simulation Engine (Falsification, Modifying, Covert Channels)
# ==============================================================================

import hashlib
import random

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ModuleNotFoundError:
        AES = None
        pad = None

class CovertTimingChannel:
    def __init__(self, mode="Plaintext", message="Hello", base_delay=180.0, scale=1.0):
        self.mode = mode
        self.message = message
        self.base_delay = base_delay * scale
        self.bit0_delay = (base_delay - 1.0) * scale
        self.bit1_delay = (base_delay + 1.0) * scale
        self.bit_stream = self._prepare_bit_stream()

    def _prepare_bit_stream(self):
        raw_bytes = self.message.encode("utf-8")
        if self.mode == "SHA3-256 Hash":
            payload = hashlib.sha3_256(raw_bytes).digest()
        elif self.mode == "AES-256-CBC Encrypted":
            if AES is None:
                raise ImportError("Neither Crypto nor Cryptodome is available. Please run: pip install pycryptodome")
            key = b"12345678901234567890123456789012"
            iv = b"1234567890123456"
            cipher = AES.new(key, AES.MODE_CBC, iv)
            payload = cipher.encrypt(pad(raw_bytes, AES.block_size))
        else:
            payload = raw_bytes

        bits = []
        for b in payload:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)
        return bits

    def get_delay_for_step(self, step_idx):
        if step_idx < len(self.bit_stream):
            bit = self.bit_stream[step_idx]
            return (self.bit1_delay if bit == 1 else self.bit0_delay), True
        return self.base_delay, False


class DataFalsificationAttack:
    def __init__(self, target_point, min_offset=4.0, max_offset=5.0, start_row=5, end_row=15):
        self.target_point = target_point
        self.min_offset = min_offset
        self.max_offset = max_offset
        self.start_row = start_row
        self.end_row = end_row

    def is_active(self, step_idx, point_name):
        return (self.start_row <= step_idx <= self.end_row) and (point_name == self.target_point)

    def falsify(self, value):
        offset = random.uniform(self.min_offset, self.max_offset)
        return round(float(value) + offset, 2)


class AttackEngine:
    def __init__(self, device_cfg: dict):
        self.cfg = device_cfg
        self.attack_type = device_cfg.get("attack_type", "Normal")
        self.sampling_rate = float(device_cfg.get("sampling_rate", 180.0))

        # Setup Covert Channel
        if self.attack_type == "Covert Timing Channel":
            mode = device_cfg.get("covert_mode", "Plaintext")
            msg = device_cfg.get("covert_msg", "Hello")
            scale = float(device_cfg.get("covert_scale", 1.0))
            self.covert_engine = CovertTimingChannel(mode, msg, self.sampling_rate, scale)
        else:
            self.covert_engine = None

        # Setup Falsification / Modifying
        self.falsify_target = device_cfg.get("falsify_point", "")
        self.f_min = float(device_cfg.get("falsify_min", 4.0))
        self.f_max = float(device_cfg.get("falsify_max", 5.0))
        self.f_start = int(device_cfg.get("falsify_start_row", 5))
        self.f_end = int(device_cfg.get("falsify_end_row", 15))
        self.modify_points = device_cfg.get("modify_points", [])

    def get_inter_packet_delay(self, step_idx: int):
        if self.covert_engine:
            return self.covert_engine.get_delay_for_step(step_idx)
        return self.sampling_rate, False

    def transform_value(self, step_idx: int, point_name: str, point_type: str, raw_val: float):
        if self.attack_type == "Falsification":
            if (self.f_start <= step_idx <= self.f_end) and (point_name == self.falsify_target):
                offset = random.uniform(self.f_min, self.f_max)
                return round(float(raw_val) + offset, 2), True, "falsification"

        elif self.attack_type == "Modifying":
            if (self.f_start <= step_idx <= self.f_end) and (point_name in self.modify_points or point_name == self.falsify_target):
                if "binary" in point_type:
                    mod_val = 0 if int(round(float(raw_val))) == 1 else 1
                    return mod_val, True, "modifying"
                else:
                    return round(float(raw_val) + 10.0, 2), True, "modifying"

        return raw_val, False, "normal"
