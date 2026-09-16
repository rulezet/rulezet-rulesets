rule CN_Tools_pc_RID2B44 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file pc.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:59:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\svchost.exe" ascii
      $s2 = "%s%08x.001" fullword ascii
      $s3 = "Qy001Service" fullword ascii
      $s4 = "/.MIKY" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}