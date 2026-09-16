rule CN_Honker_Happy_Happy_RID2F2A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Happy.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:45:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<form.*?method=\"post\"[\\s\\S]*?</form>" fullword wide
      $s2 = "domainscan.exe" fullword wide
      $s3 = "http://www.happysec.com/" wide
      $s4 = "cmdshell" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 655KB and 2 of them
}