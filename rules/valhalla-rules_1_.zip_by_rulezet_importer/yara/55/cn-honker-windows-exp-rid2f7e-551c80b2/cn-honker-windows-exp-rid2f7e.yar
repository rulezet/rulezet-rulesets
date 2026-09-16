rule CN_Honker_windows_exp_RID2F7E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file exp.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:59:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "c:\\windows\\system32\\command.com /c " fullword ascii
      $s8 = "OH,Sry.Too long command." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 220KB and all of them
}