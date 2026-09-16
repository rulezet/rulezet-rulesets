rule CN_Honker_Interception_RID2FBB : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Interception.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:09:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = ".\\dat\\Hookmsgina.dll" fullword ascii
      $s5 = "WinlogonHackEx " fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 160KB and all of them
}