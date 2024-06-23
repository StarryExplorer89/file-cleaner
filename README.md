# File Cleaner
This app repairs corruption caused by trailing data in any file due to bad downloads or external malicious tampering. The affected bytes are stored in a separate file, ensuring that no data is deleted and can be re-appended later.

<p float="left">
  <img src="/assets/file_cleaner_gui_windows.png" width="45%" />
  <img src="/assets/file_cleaner_gui_macos.png" width="45%" /> 
</p>

## Download
Download here File Cleaner v1.2
- [Download for Windows](https://github.com/StarryExplorer89/file-cleaner/releases/download/v1.2/File_Cleaner_Windows.exe)
- [Download for macOS](https://github.com/StarryExplorer89/file-cleaner/releases/download/v1.2/File_Cleaner_macOS.zip)

### Usage

1. **Select Files**
   - Click on the `Select Files` or `Select Directory` button to choose the files/folder you want to clean. Alternatively, you can drag and drop the files you want to clean.
   
2. **Cleaning Process**
   - Click on the `Clean Files` button to start the cleaning process. The application will process the selected files and clean them by removing any trailing data that causes corruption.

3. **Check Logs**
   - The window in the middle of the app will show logging information. Please check if the cleaning process went correctly. Sometimes a antivirus scanner blocks this application, which means you need to whitelist the app before you can use it.

### Supported filetypes
- MP4
- MOV
- WMV
- AVI
- MKV (in beta)
- JPG/JPEG
- PNG
- ZIP
- PDF (in beta)

## Future Updates
I sadly have little time to upgrade this application. Some features I'd like to add in the future are:
- Making MKV support stable
- Making PDF support stable
- Support for RAR files
- Support for GIF files

If you feel like contributing to this repository, please let me know!

## Documentation for Developers
Check the documentation below if you are interested in running this code yourself or if you want to contribute to this application.

### Prerequisites
- Python 3.7 or higher

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/StarryExplorer89/file-cleaner.git
   cd file-cleaner
   ```

2. **Set up a Virtual Environment**
   Create a virtual environment to manage dependencies:
   ```bash
   python -m venv env
   ```

3. **Activate the Virtual Environment**
   - On Windows:
     ```bash
     .\env\Scripts\activate
     ```
   - On macOS and Linux:
     ```bash
     source env/bin/activate
     ```

4. **Install Dependencies**
   Install the required dependencies using `pip`:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application

1. **Navigate to the Project Directory**
   Ensure you are in the project directory where the `file_cleaner_gui.py` script is located.

2. **Run the Application**
   Execute the following command to run the application:
   ```bash
   python file_cleaner_gui.py
   ```
3. **Build the Application**
   Execute the following command to build the application:
   ```bash
   pyinstaller --windowed --additional-hooks-dir=. --icon=assets/app_icon.ico -F file_cleaner_gui.py
   ```
   Note: If you run this on Windows, it will create a .exe file, where as if you run it on macOS, it will create a .app file.

### Additional Information

- **Virtual Environment Management**
  Make sure to always activate the virtual environment before running the application to ensure the correct dependencies are used.

### Troubleshooting

- **Tkinter Not Found**
  If Tkinter is not found, you may need to install it separately:
  - On Debian-based systems:
    ```bash
    sudo apt-get install python3-tk
    ```
  - On Red Hat-based systems:
    ```bash
    sudo yum install python3-tkinter
    ```

Feel free to open an issue on the repository if you encounter any problems or have any questions.
