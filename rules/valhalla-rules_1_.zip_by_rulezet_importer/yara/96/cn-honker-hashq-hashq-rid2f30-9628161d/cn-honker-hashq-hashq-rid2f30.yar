rule CN_Honker_hashq_Hashq_RID2F30 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Hashq.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:46:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Hashq.exe" fullword wide
      $s5 = "CnCert.Net" fullword wide
      $s6 = "Md5 query tool" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and all of them
}