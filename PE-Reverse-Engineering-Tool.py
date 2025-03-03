# -*- coding: utf-8 -*-
"""
Created on Mon Mar 3 8:10:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("PE Analysis Tool ")
print(Fore.GREEN+font)



import os
import psutil
import pefile

def analyze_pe_file(file_path):
    """Analyzes the PE (Portable Executable) file and prints basic information."""
    try:
        pe = pefile.PE(file_path)
        print(f"Analyzing {file_path}...\n")
        
        # File Info
        print(f"File: {file_path}")
        print(f"Machine: {pe.FILE_HEADER.Machine}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        
        # Section Info
        print("\nSections:")
        for section in pe.sections:
            print(f"  - Name: {section.Name.decode().strip()}")
            print(f"    Virtual Address: {hex(section.VirtualAddress)}")
            print(f"    Size of Raw Data: {section.SizeOfRawData} bytes")
        
        # Imports (External Libraries)
        print("\nImports:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"  - Library: {entry.dll.decode()}")
            for imp in entry.imports:
                print(f"    Function: {imp.name.decode() if imp.name else 'None'}")
    
    except Exception as e:
        print(f"Error analyzing PE file: {e}")

def monitor_process(file_path):
    """Monitor a running process created from the given executable."""
    try:
        # Start the executable file
        process = psutil.Popen(file_path)

        print(f"Monitoring process {process.pid}...\n")
        print(f"Process Name: {process.name()}")
        print(f"Process Command Line: {process.cmdline()}")
        
        # Monitor the process until it exits
        while process.is_running():
            print(f"\nProcess {process.pid} is running...")
            print(f"Memory Usage: {process.memory_info().rss / 1024 / 1024:.2f} MB")
            print(f"CPU Usage: {process.cpu_percent(interval=1)}%")
            print(f"Open File Descriptors: {len(process.open_files())}")
            print(f"Status: {process.status()}")
            print("=" * 40)

        print(f"\nProcess {process.pid} has finished executing.")
    
    except Exception as e:
        print(f"Error monitoring process: {e}")

def main():
    
    
    # Get file path from user
    file_path = input("Please enter the path of the executable or binary to analyze:").strip()
    
    if not os.path.isfile(file_path):
        print("Error: The file does not exist or is not a valid file.")
        return

    # Check if the file is a PE file (Windows executables)
    if file_path.lower().endswith('.exe'):
        analyze_pe_file(file_path)
    else:
        print(f"File {file_path} is not a recognized executable for PE analysis.")
    
    # Ask the user if they want to monitor the process while it runs
    user_input = input(f"Would you like to monitor the process of {file_path}? (y/n): ").strip().lower()
    if user_input == 'y':
        monitor_process(file_path)
    else:
        print("Exiting the tool.")

if __name__ == "__main__":
    main()
