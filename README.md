# ProcScout

ProcScout is a utility designed to automate the use of Procmon (Process Monitor) to ssist Blue Teams with detecting potential DLL hijacking vulnerabilities (via custom config). It simplifies the process by automating the extraction and analysis of process monitoring logs. UAC will be prompted for non-elevated accounts running the program.

## Features

- Automates the extraction and execution of Procmon64.exe
- Checks Safe DLL Search Mode status
- Converts Procmon logs from PML to CSV
- Detects writable directories for potential DLL hijacking

  ![ProcScout Example](/example.jpeg)

## Installation

To install ProcScout, follow these steps:

1. Clone the repository:
   git clone https://github.com/Lenard-Code/ProcScout.git
2. Navigate to the project directory:
  cd ProcScout
3. Build the project using Visual Studio. (Procmon64.exe will need to be placed within the build folder)

## Usage
Run the following command from an elevated command prompt (if not, UAC will be presented):
procscout.exe

ProcScout will:
1. Extract and run Procmon64.exe 
2. Capture process activity for 60 seconds (Default, manual change if needed longer)
3. Convert the captured PML log to CSV format
4. Check the CSV log for writable directories that can be exploited for DLL hijacking

##License
ProcScout is licensed under the MIT License. See the LICENSE file for more details.
