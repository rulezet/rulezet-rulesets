rule CN_Honker_pr_debug_RID2E0F : CHINA DEMO EXE FILE HKTL T1087_002 T1136 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file debug.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:58:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1087_002, T1136"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-->Got WMI process Pid: %d " ascii
      $s2 = "This exploit will execute \"net user temp 123456 /add & net localg" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 820KB and all of them
}