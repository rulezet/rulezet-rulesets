rule APT28_CHOPSTICK_RID2B67 : APT DEMO EXE FILE G0007 RUSSIA {
   meta:
      description = "Detects a malware that behaves like CHOPSTICK mentioned in APT28 report"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/gui/file/e8e87873455839080b369a5497c115886d1b0b6cfb6dabc9f040fef0c7e4e737/detection"
      date = "2015-06-02 09:05:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, G0007, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "jhuhugit.tmp" fullword ascii
      $s8 = "KERNEL32.dll" fullword ascii
      $s9 = "IsDebuggerPresent" fullword ascii
      $s10 = "IsProcessorFeaturePresent" fullword ascii
      $s11 = "TerminateProcess" fullword ascii
      $s13 = "DeleteFileA" fullword ascii
      $s15 = "GetProcessHeap" fullword ascii
      $s16 = "!This program cannot be run in DOS mode." fullword ascii
      $s17 = "LoadLibraryA" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 722KB and all of them
}