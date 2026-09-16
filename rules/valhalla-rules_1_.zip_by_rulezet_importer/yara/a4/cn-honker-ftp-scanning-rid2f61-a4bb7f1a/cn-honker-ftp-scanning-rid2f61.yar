rule CN_Honker_FTP_scanning_RID2F61 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file FTP_scanning.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:54:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "CNotSupportedE" fullword ascii
      $s2 = "nINet.dll" fullword ascii
      $s9 = "?=MODULE" fullword ascii
      $s13 = "MSIE 6*" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 550KB and all of them
}