rule CN_Honker_Oracle_v1_0_Oracle_RID3167 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Oracle.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:21:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "!http://localhost/index.asp?id=zhr" fullword ascii
      $s2 = "OnGetPassword" fullword ascii
      $s3 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3455KB and all of them
}