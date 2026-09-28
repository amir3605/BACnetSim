# Advanced Multi-Device BACnet/IP Dataset & Attack Simulator

## Description
This repository contains a research-oriented software implementation for generating BACnet/IP traffic datasets and simulating covert timing channel attacks. This tool is designed to address limitations in prior BACnet/IP traffic generation studies by providing a modular, multi-device, and graphical interface for researchers.

The simulator facilitates:
- Generation of synthetic BACnet/IP traffic.
- Implementation of Covert Timing Channels.
- Simulation of various attack scenarios on BACnet/IP devices.

## Features
- **PyQt6 GUI:** User-friendly interface for configuring simulation parameters.
- **Multi-Device Support:** Generate traffic and attacks for multiple concurrent BACnet devices.
- **Attack Engine:** Modular engine for integrating different attack payloads.
- **Dataset Export:** Capabilities for generating ground-truth data and PCAP files for analysis.

## Prerequisites
- Python 3.x
- PyQt6
- (Additional dependencies listed in `requirements.txt`)

## Installation
1. Clone the repository:
```bash
   git clone <your-repository-url>
   cd bacnet_traffic_generator2
   
