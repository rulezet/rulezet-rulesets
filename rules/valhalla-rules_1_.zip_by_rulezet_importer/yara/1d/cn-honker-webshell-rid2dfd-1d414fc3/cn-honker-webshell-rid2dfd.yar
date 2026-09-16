rule CN_Honker_Webshell_RID2DFD : CHINA DEMO EXE FILE HKTL T1505_003 WEBSHELL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Webshell.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:55:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Windows NT users: Please note that having the WinIce/SoftIce" fullword ascii
      $s2 = "Do you want to cancel the file download?" fullword ascii
      $s3 = "Downloading: %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 381KB and all of them
}