# ==============================================================================
# File: bacnet_gen/ui.py
# Description: Advanced Multi-Device BACnet/IP Dataset Generator GUI
# ==============================================================================

import os
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QGroupBox, QLabel, QLineEdit, QSpinBox, QDoubleSpinBox,
    QComboBox, QCheckBox, QPushButton, QTableWidget, QTableWidgetItem,
    QFileDialog, QMessageBox, QTextEdit, QScrollArea, QHeaderView
)
from PyQt6.QtCore import Qt
import pandas as pd
from .traffic_generator import TrafficGenerator

OBJECT_TYPES = [
    "analog_input",
    "analog_output",
    "analog_value",
    "binary_input",
    "binary_output",
    "binary_value"
]

class DeviceConfigWidget(QWidget):
    def __init__(self, dev_id=1, default_name="Chiller_Controller"):
        super().__init__()
        self.dev_id = dev_id
        self.init_ui(default_name)

    def init_ui(self, default_name):
        layout = QVBoxLayout(self)

        # Basic Net Info
        net_group = QGroupBox(f"Device Network Config ({default_name})")
        net_lay = QHBoxLayout()
        
        self.name_edit = QLineEdit(default_name)
        self.ip_edit = QLineEdit(f"192.168.1.{100 + self.dev_id}")
        self.mac_edit = QLineEdit(f"00:0c:29:ab:cd:{self.dev_id:02x}")
        self.devid_spin = QSpinBox()
        self.devid_spin.setRange(1, 999999)
        self.devid_spin.setValue(1000 + self.dev_id)
        
        self.rate_spin = QDoubleSpinBox()
        self.rate_spin.setRange(0.1, 3600.0)
        self.rate_spin.setValue(180.0 if "Chiller" in default_name else 5.0)
        self.rate_spin.setSuffix(" sec")

        net_lay.addWidget(QLabel("Name:"))
        net_lay.addWidget(self.name_edit)
        net_lay.addWidget(QLabel("IP:"))
        net_lay.addWidget(self.ip_edit)
        net_lay.addWidget(QLabel("MAC:"))
        net_lay.addWidget(self.mac_edit)
        net_lay.addWidget(QLabel("BACnet ID:"))
        net_lay.addWidget(self.devid_spin)
        net_lay.addWidget(QLabel("Normal Interval:"))
        net_lay.addWidget(self.rate_spin)
        net_group.setLayout(net_lay)
        layout.addWidget(net_group)

        # CSV Data Source & Points Table
        points_group = QGroupBox("Data Points & Objects Configuration")
        pts_lay = QVBoxLayout()
        
        csv_bar = QHBoxLayout()
        self.csv_path_edit = QLineEdit()
        self.csv_path_edit.setPlaceholderText("Optional: Select CSV data file for realistic values...")
        btn_browse_csv = QPushButton("Browse CSV")
        btn_browse_csv.clicked.connect(self.load_csv_points)
        csv_bar.addWidget(QLabel("CSV File:"))
        csv_bar.addWidget(self.csv_path_edit)
        csv_bar.addWidget(btn_browse_csv)
        pts_lay.addLayout(csv_bar)

        # Table for BACnet Object Types
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Point Name", "BACnet Object Type", "Instance #", "Default / Fallback Val"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        pts_lay.addWidget(self.table)

        tbl_btns = QHBoxLayout()
        btn_add_pt = QPushButton("+ Add Point")
        btn_add_pt.clicked.connect(self.add_point_row)
        btn_del_pt = QPushButton("- Remove Selected")
        btn_del_pt.clicked.connect(self.remove_point_row)
        tbl_btns.addWidget(btn_add_pt)
        tbl_btns.addWidget(btn_del_pt)
        tbl_btns.addStretch()
        pts_lay.addLayout(tbl_btns)
        
        points_group.setLayout(pts_lay)
        layout.addWidget(points_group)

        # Attack Engine Settings
        atk_group = QGroupBox("Attack & Covert Channel Configuration")
        atk_lay = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Attack Type:"))
        self.atk_combo = QComboBox()
        self.atk_combo.addItems(["Normal", "Falsification", "Modifying", "Covert Timing Channel"])
        self.atk_combo.currentIndexChanged.connect(self.toggle_attack_fields)
        row1.addWidget(self.atk_combo)
        atk_lay.addLayout(row1)

        # Falsification Box
        self.falsify_box = QWidget()
        f_lay = QHBoxLayout(self.falsify_box)
        self.f_target = QLineEdit("ChilledWaterSupplyTemp")
        self.f_min = QDoubleSpinBox()
        self.f_min.setValue(4.0)
        self.f_max = QDoubleSpinBox()
        self.f_max.setValue(5.0)
        self.f_start = QSpinBox()
        self.f_start.setValue(5)
        self.f_end = QSpinBox()
        self.f_end.setValue(15)
        f_lay.addWidget(QLabel("Target Point:"))
        f_lay.addWidget(self.f_target)
        f_lay.addWidget(QLabel("Offset Min:"))
        f_lay.addWidget(self.f_min)
        f_lay.addWidget(QLabel("Max:"))
        f_lay.addWidget(self.f_max)
        f_lay.addWidget(QLabel("Rows (Start-End):"))
        f_lay.addWidget(self.f_start)
        f_lay.addWidget(self.f_end)
        atk_lay.addWidget(self.f_box_wrap(self.falsify_box, "Falsification Attack Parameters"))

        # Covert Channel Box
        self.covert_box = QWidget()
        c_lay = QVBoxLayout(self.covert_box)
        c_row1 = QHBoxLayout()
        self.c_mode = QComboBox()
        self.c_mode.addItems(["Plaintext", "SHA3-256 Hash", "AES-256-CBC Encrypted"])
        self.c_msg = QLineEdit("     Hello Bob I am Alice")
        c_row1.addWidget(QLabel("Encoding Mode:"))
        c_row1.addWidget(self.c_mode)
        c_row1.addWidget(QLabel("Secret Message:"))
        c_row1.addWidget(self.c_msg)
        c_lay.addLayout(c_row1)

        c_row2 = QHBoxLayout()
        self.c_scale = QDoubleSpinBox()
        self.c_scale.setRange(0.01, 10.0)
        self.c_scale.setValue(1.0)
        self.c_scale.setSuffix("x (Scale)")
        c_row2.addWidget(QLabel("Timing Delays: [Bit 0: T-1s | Bit 1: T+1s | Normal: Normal intervals]"))
        c_row2.addWidget(QLabel("Speed Scale:"))
        c_row2.addWidget(self.c_scale)
        c_row2.addStretch()
        c_lay.addLayout(c_row2)
        atk_lay.addWidget(self.f_box_wrap(self.covert_box, "Covert Timing Channel Parameters"))

        atk_group.setLayout(atk_lay)
        layout.addWidget(atk_group)

        self.add_default_sample_points(default_name)
        self.toggle_attack_fields()

    def f_box_wrap(self, widget, title):
        box = QGroupBox(title)
        v = QVBoxLayout(box)
        v.addWidget(widget)
        return box

    def toggle_attack_fields(self):
        atk = self.atk_combo.currentText()
        self.falsify_box.parentWidget().setVisible(atk in ["Falsification", "Modifying"])
        self.covert_box.parentWidget().setVisible(atk == "Covert Timing Channel")

    def add_point_row(self, name="", obj_type="analog_input", inst=0, def_val=0.0):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        self.table.setItem(row, 0, QTableWidgetItem(str(name)))
        
        combo = QComboBox()
        combo.addItems(OBJECT_TYPES)
        combo.setCurrentText(obj_type)
        self.table.setCellWidget(row, 1, combo)
        
        spin_inst = QSpinBox()
        spin_inst.setRange(0, 99999)
        spin_inst.setValue(int(inst))
        self.table.setCellWidget(row, 2, spin_inst)

        self.table.setItem(row, 3, QTableWidgetItem(str(def_val)))

    def remove_point_row(self):
        curr = self.table.currentRow()
        if curr >= 0:
            self.table.removeRow(curr)

    def load_csv_points(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Device CSV", "", "CSV Files (*.csv)")
        if path:
            self.csv_path_edit.setText(path)
            try:
                df = pd.read_csv(path)
                self.table.setRowCount(0)
                for idx, col in enumerate(df.columns):
                    sample_val = df[col].iloc[0] if len(df) > 0 else 0.0
                    obj_t = "analog_input"
                    if str(sample_val).lower() in ["0", "1", "true", "false"]:
                        obj_t = "binary_input"
                    self.add_point_row(col, obj_t, idx, sample_val)
            except Exception as e:
                QMessageBox.warning(self, "CSV Error", f"Failed to parse CSV: {e}")

    def add_default_sample_points(self, default_name):
        if "Chiller" in default_name:
            self.add_point_row("ChilledWaterSupplyTemp", "analog_input", 7, 6.8)
            self.add_point_row("ChilledWaterReturnTemp", "analog_input", 8, 12.2)
            self.add_point_row("ChillerOnOffStatus", "binary_output", 0, 1)
        elif "AHU" in default_name:
            self.add_point_row("SupplyAirTemp", "analog_input", 1, 18.5)
            self.add_point_row("SupplyFanStatus", "binary_value", 1, 1)
        else:
            self.add_point_row("Sensor_Reading", "analog_value", 0, 24.0)

    def get_config(self):
        pts = []
        for r in range(self.table.rowCount()):
            name_item = self.table.item(r, 0)
            val_item = self.table.item(r, 3)
            combo = self.table.cellWidget(r, 1)
            spin = self.table.cellWidget(r, 2)
            
            p_name = name_item.text().strip() if name_item else f"Point_{r}"
            p_type = combo.currentText() if combo else "analog_input"
            p_inst = spin.value() if spin else r
            try:
                p_val = float(val_item.text()) if val_item else 0.0
            except ValueError:
                p_val = 0.0
                
            pts.append({"name": p_name, "type": p_type, "instance": p_inst, "default_val": p_val})

        return {
            "name": self.name_edit.text(),
            "ip": self.ip_edit.text(),
            "mac": self.mac_edit.text(),
            "device_id": self.devid_spin.value(),
            "port": 47808,
            "sampling_rate": self.rate_spin.value(),
            "csv_path": self.csv_path_edit.text() or None,
            "points": pts,
            "attack_type": self.atk_combo.currentText(),
            "falsify_point": self.f_target.text(),
            "falsify_min": self.f_min.value(),
            "falsify_max": self.f_max.value(),
            "falsify_start_row": self.f_start.value(),
            "falsify_end_row": self.f_end.value(),
            "modify_points": ["ChilledWaterPumpStatus", "CondenserWaterPumpStatus"],
            "modify_start_row": self.f_start.value(),
            "modify_end_row": self.f_end.value(),
            "covert_mode": self.c_mode.currentText(),
            "covert_msg": self.c_msg.text(),
            "covert_scale": self.c_scale.value()
        }


class BACnetGeneratorUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BACnet Multi-Device Traffic & Attack Simulator (PyQt6)")
        self.resize(1150, 800)
        self.device_widgets = []
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # Global Config Bar
        g_box = QGroupBox("Global Simulation Settings")
        g_lay = QHBoxLayout()
        self.srv_ip = QLineEdit("192.168.1.100")
        self.srv_port = QSpinBox()
        self.srv_port.setRange(1, 65535)
        self.srv_port.setValue(47808)
        self.max_pkts = QSpinBox()
        self.max_pkts.setRange(1, 100000)
        self.max_pkts.setValue(30)
        self.chk_discovery = QCheckBox("Include Who-Is Discovery")
        self.chk_discovery.setChecked(True)

        g_lay.addWidget(QLabel("BMS Server IP:"))
        g_lay.addWidget(self.srv_ip)
        g_lay.addWidget(QLabel("Port:"))
        g_lay.addWidget(self.srv_port)
        g_lay.addWidget(QLabel("Max Steps/Device:"))
        g_lay.addWidget(self.max_pkts)
        g_lay.addWidget(self.chk_discovery)
        g_box.setLayout(g_lay)
        main_layout.addWidget(g_box)

        # Device Tabs
        tab_header = QHBoxLayout()
        tab_header.addWidget(QLabel("<b>Configured BACnet Devices:</b>"))
        btn_add_tab = QPushButton("+ Add New Controller Device")
        btn_add_tab.clicked.connect(self.add_device_tab)
        btn_del_tab = QPushButton("- Remove Current Controller")
        btn_del_tab.clicked.connect(self.remove_device_tab)
        tab_header.addWidget(btn_add_tab)
        tab_header.addWidget(btn_del_tab)
        tab_header.addStretch()
        main_layout.addLayout(tab_header)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Default standard devices from the research paper
        self.create_tab_device("Chiller_Controller")
        self.create_tab_device("AHU_Controller")
        self.create_tab_device("VAV_Controller")
        self.create_tab_device("Weather_Station")

        # Action Buttons & Status Log
        act_box = QHBoxLayout()
        self.pcap_out = QLineEdit("bacnet_generated_dataset.pcap")
        self.csv_out = QLineEdit("bacnet_ground_truth.csv")
        btn_gen = QPushButton("🚀 Generate Multi-Device Dataset")
        btn_gen.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 10px;")
        btn_gen.clicked.connect(self.run_generation)

        act_box.addWidget(QLabel("Output PCAP:"))
        act_box.addWidget(self.pcap_out)
        act_box.addWidget(QLabel("Output Ground-Truth CSV:"))
        act_box.addWidget(self.csv_out)
        act_box.addWidget(btn_gen)
        main_layout.addLayout(act_box)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(150)
        main_layout.addWidget(self.log_box)

    def create_tab_device(self, name):
        dev_idx = len(self.device_widgets) + 1
        w = DeviceConfigWidget(dev_id=dev_idx, default_name=name)
        self.device_widgets.append(w)
        self.tabs.addTab(w, name)

    def add_device_tab(self):
        dev_idx = len(self.device_widgets) + 1
        self.create_tab_device(f"Controller_{dev_idx}")

    def remove_device_tab(self):
        curr = self.tabs.currentIndex()
        if self.tabs.count() > 1 and curr >= 0:
            self.tabs.removeTab(curr)
            self.device_widgets.pop(curr)

    def run_generation(self):
        global_cfg = {
            "server_ip": self.srv_ip.text(),
            "server_mac": "00:0c:29:ee:ff:00",
            "server_port": self.srv_port.value(),
            "max_packets_per_device": self.max_pkts.value(),
            "include_discovery": self.chk_discovery.isChecked()
        }

        device_cfgs = [w.get_config() for w in self.device_widgets]

        self.log_box.append("Generating multi-device dataset...")
        try:
            gen = TrafficGenerator(global_cfg, device_cfgs)
            res = gen.generate(self.pcap_out.text(), self.csv_out.text())

            msg = (
                f"✅ <b>Dataset Generated Successfully!</b><br>"
                f"Total Packets: {res['total_packets']}<br>"
                f"Total Ground-Truth Labels: {res['total_labels']}<br>"
                f"Total Attack Records: {res['attack_count']}<br>"
                f"PCAP: {res['pcap_path']}<br>"
                f"CSV: {res['csv_path']}"
            )
            self.log_box.append(msg)
            QMessageBox.information(self, "Success", "BACnet Dataset Generated Successfully!")

        except Exception as e:
            err_msg = f"❌ Generation Failed: {e}"
            self.log_box.append(err_msg)
            QMessageBox.critical(self, "Generation Error", err_msg)
