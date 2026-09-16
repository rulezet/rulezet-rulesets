rule Dos_Down64_RID2A98 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Down64.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 07:05:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
      $s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
      $s3 = "C:\\Windows\\Temp\\" wide
      $s4 = "ProcessXElement" fullword ascii
      $s8 = "down.exe" fullword wide
      $s20 = "set_Timer1" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and all of them
}