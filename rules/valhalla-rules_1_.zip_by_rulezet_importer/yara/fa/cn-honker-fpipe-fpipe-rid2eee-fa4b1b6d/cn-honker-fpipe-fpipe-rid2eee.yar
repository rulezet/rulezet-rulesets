rule CN_Honker_Fpipe_FPipe_RID2EEE : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file FPipe.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:35:31"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Unable to create TCP listen socket. %s%d" fullword ascii
      $s2 = "http://www.foundstone.com" fullword ascii
      $s3 = "%s %s port %d. Address is already in use" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and all of them
}