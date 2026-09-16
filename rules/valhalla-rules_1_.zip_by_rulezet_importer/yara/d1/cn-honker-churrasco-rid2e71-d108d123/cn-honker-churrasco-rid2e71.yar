rule CN_Honker_Churrasco_RID2E71 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Churrasco.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:14:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "HEAD9 /" ascii
      $s1 = "logic_er" fullword ascii
      $s6 = "proggam" fullword ascii
      $s16 = "DtcGetTransactionManagerExA" fullword ascii
      $s17 = "GetUserNameA" fullword ascii
      $s18 = "OLEAUT" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1276KB and all of them
}