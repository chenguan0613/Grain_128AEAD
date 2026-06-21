
# Cryptography Assignment

## Project Architecture

```bash
GRAIN_128AEAD/
│
├── crypto_engine/
│   ├── __init__.py
│   └── grain_v2.py
├── data/
│   ├── case6.key
│   └── keywrapping
│
├── file_io/
│   ├── __init__.py
│   └── file_handler.py
│
├── key_management/
│   ├── __init__.py
│   └── wrapper.py
│
├── utils/
│   ├── __init__.py
│   └── data_converters.py
│
├── requirements.txt
├── main.py
├── ui_grain.py
├── grain_gui.ui
└── style.qss
```

## System Prerequisites

```bash
Python >=3.13
```

## Step 1: Preparation

Use Python Virtual Environment to avoid dependency conflicts. Execute the following commands sequentially:

* Navigate to the project folder: cd path/this project folder
* Create a virtual environment: `python -m venv .venv`
* Activate the virtual environment:
  * For windows: `.\.venv\bin\Activate.ps1`
  * For macOS/Linux: `source .venv/bin/activate`
* Install all required dependencies: `pip install -r requirements.txt`

## Step 2: Launching the Application

Once the environment is successfully configured and the dependencies are installed, you can run main.py to wake up the GUI.

* Run the program: `python main.py`
* Do not close the background terminal, as the relevant execution logs will be printed there.

## Step 3: Executing Test Cases via GUI

* **Parameter Initialization:** In the top panel, manually input a 32-character hexadecimal Key and a 24-character hexadecimal IV, or simply click the "Generate Key" and "Generate IV" buttons.
* **Algorithm Internal States Monitor:** If you do the encryption or decryption, the after loading state and after initialization state of the LFSR and NFSR will automatically be displayed in the box.
* **Manual Text Mode:** In the manual encryption/decryption part, you can do the encryption and decryption manually. If you are encrypted, you can enter your plaintext in the Encryption/Decryption box, choose the Encryption radio and click the Encrypt button to encrypt.  Then you can get the ciphertext in the Output (Hex) with the IV prefix. If you are decrypted, you can enter your ciphertext with IV prefix in the Encryption/Decryption box, choose the Decryption radio and click the Decrypt button to encrypt. Then you can get the plaintext in the Output (ASCII)
* **File I/O Mode:** Choose the Encryption/Decryption radio to determine encryption or decryption. If encryption, click the “Load” and choose the path of .txt file (plaintext) and click the “Save” to choose the .enc file (ciphertext)’s save path. Then, click the “Encrypt” button to encrypt. If decryption, click the “Load” and choose the path of .enc file (ciphertext) and click the “Save” to choose the .dec file (plaintext)’s save path. Then, click the “Decrypt” button to decrypt.
* **Key Wrapping Mode:** Enter a strong custom password and your Associated Data (AD). You can manually enter the iteration count, nonce and salt or neglect it and the system will automatically generate their value at random. Click “Wrap and Save Key”, the system will bind the AD via AES-CCM authentication and save .key JSON file to your local directory “data”. What’s more, to do the unwrapping and authentication, you can clear the key input box, enter the correct password and AD, and click “Load Key” to select your target .key file’s path. Then you can successfully load the key into the key input box.
