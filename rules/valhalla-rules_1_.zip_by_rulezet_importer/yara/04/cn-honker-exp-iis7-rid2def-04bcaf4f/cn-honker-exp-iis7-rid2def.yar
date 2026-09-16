rule CN_Honker_exp_iis7_RID2DEF : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file iis7.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:53:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\\\localhost" fullword ascii
      $s1 = "iis.run" fullword ascii
      $s3 = ">Could not connecto %s" fullword ascii
      $s4 = "WinSta0\\Default" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them
}