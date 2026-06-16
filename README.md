# Cryptography-Assignment


GRAIN_128AEAD/
├── crypto_engine/          #Cryptographic Engine Module
│ └── grain_v2.py           #Grain-128AEADv2 Underlying Core Algorithm Implementation
├── key_management/         #Key Management Module
│ └── wrapper.py            #PBKDF2 Derivation and AES-CCM Packaging Logic
├── file_io/                #File input/output Module
│ └── file_handler.py       #Key file and ciphertext read/write processing
├── utils/                  #Tool Module
│ └── data_converters.py    #Unified handling of Hex/ASCII/Bits format conversion
├── data/                   #Local storage directory (stores .key, .enc, .dec files)
├── main.py                 #Application entry point and GUI event dispatch core
├── ui_grain.py             #Qt Designer compiled interface code
└── style.qss               #GUI visual style sheet


Use PyQt6 to implement the GUI

Install PySide6 using pip install PySide6 (use pyside6-designer to design the GUI)

use pyinstaller to package the application into an executable file (pip install pyinstaller) and run:

pyinstaller --noconsole --onefile --add-data "style.qss;." main.py

keywrapping