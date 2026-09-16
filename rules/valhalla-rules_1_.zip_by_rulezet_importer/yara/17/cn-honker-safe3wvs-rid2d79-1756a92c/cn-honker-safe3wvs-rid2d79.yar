rule CN_Honker_Safe3WVS_RID2D79 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Safe3WVS.EXE"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:33:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "2TerminateProcess" fullword ascii
      $s1 = "mscoreei.dll" fullword ascii
      $s7 = "SafeVS.exe" fullword wide
      $s8 = "www.safe3.com.cn" fullword wide
      $s20 = "SOFTWARE\\Classes\\Interface\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}