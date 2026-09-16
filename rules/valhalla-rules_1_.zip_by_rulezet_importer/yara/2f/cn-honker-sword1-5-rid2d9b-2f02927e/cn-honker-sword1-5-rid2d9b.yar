rule CN_Honker_Sword1_5_RID2D9B : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Sword1.5.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:39:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://www.md5.com.cn" fullword wide
      $s2 = "ListBox_Command" fullword wide
      $s3 = "\\Set.ini" wide
      $s4 = "OpenFileDialog1" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 740KB and all of them
}