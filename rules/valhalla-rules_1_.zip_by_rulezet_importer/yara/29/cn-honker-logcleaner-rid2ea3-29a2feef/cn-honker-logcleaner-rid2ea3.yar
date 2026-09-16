rule CN_Honker_LogCleaner_RID2EA3 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file LogCleaner.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:23:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = ".exe <ip> [(path]" fullword ascii
      $s4 = "LogCleaner v" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and all of them
}