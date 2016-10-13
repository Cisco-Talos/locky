# LockyDump

##LockyDump Requirements

LockyDump is a PE32 Windows binary application that is used for extracting embedded configurations from the Locky malware family, which requires execution of the malware to allow for the extraction of these values from memory. This limits the analysis environment to Windows systems, and to one that can be compromised by Locky.

##LockyDump Process Methodology

Locky has been distributed as both Win32 executables and DLLs and as such, we created LockyDump to utilize two separate analysis methods. DLL files are started with LoadLibrary, which enables the unpacker to expose the Locky code and lets the initialization code decrypt the configuration. Once the decrypted configuration is exposed LockyDump locates it and prints to stdout.

The versions of Locky delivered as EXE files required a different approach to analysis, which is accomplished by executing the malware with LockyDump configured to debug it. The malware is allowed to run until the true code is detected, at which point LockyDump freezes its execution. LockyDump then locates the configuration information and prints it to stdout.

##Optional Features:

This is a list of optional features which can be enabled at runtime of LockyDump to extract additional information from the Locky sample. These are configured using Windows environment variables which you can set prior to the execution of LockyDump:

```
set LOCKY_DUMP_VERBOSE=1

set LOCKY_DUMP_SAVE=1
```

Verbose Output - Locky configurations include two templates: one for the ransom note image and one for the ransom note HTML. By default LockyDump does not print these two fields because they increase the size of the output significantly. If the environment variable LOCKY_DUMP_VERBOSE is present then both ransom note templates will be printed to stdout.

Locky Unpacking - Locky binaries are protected with various packers, which makes static analysis challenging. If the environment variable LOCKY_DUMP_SAVE is set then the unpacked Locky file is saved as DUMPED_IMAGE.DLL in the current working directory. The proceeding file will always be ‘DUMPED_IMAGE.DLL’

##Execution Instructions

With LockyDump a user can take a virtualized instance of Microsoft Windows, place a known Locky sample within it, and run LockyDump against it. The use of a virtualized environment is highly recommended as LockyDump will execute Locky to allow the extraction of the configuration information from memory. 

LockyDump is executed via command line using the following syntax:

`LockyDump.exe sample.exe [args to sample.exe]`
