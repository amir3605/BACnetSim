# ==============================================================================
# File: run_gui.py
# Project: Advanced Multi-Device BACnet/IP Dataset & Attack Simulator
# ------------------------------------------------------------------------------
# Description:
#   This module provides the graphical user interface for a research-oriented 
#   BACnet/IP dataset generator. This implementation presents a novel 
#   methodological approach for covert timing channel research and attack 
#   simulation, specifically developed to address limitations in prior 
#   BACnet/IP traffic generation studies.
#
# Author: Seyed Amirhossein Mosavi (PhD Candidate)
# Institution: Islamic Azad University
# ORCID: https://orcid.org/0009-0008-9578-2215
# Email: amirhousein.mousavi@iau.ac.ir
#
# License: Research Prototype / Academic Contribution
# ==============================================================================

import sys
import signal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
from bacnet_gen.ui import BACnetGeneratorUI

def sigint_handler(*args):
    """Handle Ctrl+C from terminal cleanly."""
    print("\n[INFO] Exiting application via Ctrl+C...")
    QApplication.quit()

def main():
    # Setup signal handler to capture Ctrl+C
    signal.signal(signal.SIGINT, sigint_handler)
    
    app = QApplication(sys.argv)
    
    # QTimer allows the Python interpreter to periodically interrupt 
    # the event loop to process system signals like SIGINT
    timer = QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)
    
    window = BACnetGeneratorUI()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
