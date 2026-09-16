rule CN_Honker_SqlMap_Python_Run_RID318A : CHINA DEMO EXE FILE HKTL SCRIPT T1059_006 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Run.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:26:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".\\Run.log" fullword ascii
      $s2 = "[root@Hacker~]# Sqlmap " fullword ascii
      $s3 = "%sSqlmap %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of them
}