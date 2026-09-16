rule CN_Honker_ScanHistory_RID2F3E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ScanHistory.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:48:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ScanHistory.exe" fullword wide
      $s2 = ".\\Report.dat" fullword wide
      $s3 = "select  * from  Results order by scandate desc" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}