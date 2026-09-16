rule CN_Honker_ManualInjection_RID30C8 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ManualInjection.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://127.0.0.1/cookie.asp?fuck=" fullword ascii
      $s16 = "http://Www.cnhuker.com | http://www.0855.tv" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}