rule CN_Honker_Hookmsgina_RID2ED7 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Hookmsgina.dll"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:31:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\pipe\\WinlogonHack" fullword ascii
      $s2 = "%s?host=%s&domain=%s&user=%s&pass=%s&port=%u" fullword ascii
      $s3 = "Global\\WinlogonHack_Load%u" fullword ascii
      $s4 = "Hookmsgina.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}