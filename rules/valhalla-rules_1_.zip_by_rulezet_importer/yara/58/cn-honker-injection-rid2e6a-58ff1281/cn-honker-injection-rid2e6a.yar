rule CN_Honker_Injection_RID2E6A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Injection.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:13:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://127.0.0.1/6kbbs/bank.asp" fullword ascii
      $s7 = "jmPost.asp" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 220KB and all of them
}