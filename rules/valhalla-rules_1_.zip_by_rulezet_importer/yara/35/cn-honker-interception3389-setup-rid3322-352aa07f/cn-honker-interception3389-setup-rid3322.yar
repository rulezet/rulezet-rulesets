rule CN_Honker_Interception3389_setup_RID3322 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file setup.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:34:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\%s" fullword ascii
      $s1 = "%s\\temp\\temp%d.bat" fullword ascii
      $s5 = "EventStartShell" fullword ascii
      $s6 = "del /f /q \"%s\"" fullword ascii
      $s7 = "\\wminotify.dll" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}