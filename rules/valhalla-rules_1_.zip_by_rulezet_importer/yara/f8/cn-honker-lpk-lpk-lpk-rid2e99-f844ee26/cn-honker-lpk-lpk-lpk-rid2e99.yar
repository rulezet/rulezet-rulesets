rule CN_Honker__LPK_LPK_LPK_RID2E99 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - from files LPK.DAT, LPK.DAT, LPK.DAT"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:21:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b2ab50753006f62965bba83460e3960ca7e1926"
      hash2 = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\WINDOWS\\system32\\cmd.exe" fullword wide
      $s2 = "Password error!" fullword ascii
      $s3 = "\\sathc.exe" ascii
      $s4 = "\\sothc.exe" ascii
      $s5 = "\\lpksethc.bat" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1057KB and all of them
}