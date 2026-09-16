rule ustrrefadd_RID2B45 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file ustrrefadd_RID2B45.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:59:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "E-Mail  : admin@luocong.com" fullword ascii
      $s1 = "Homepage: http://www.luocong.com" fullword ascii
      $s2 = ": %d  -  " fullword ascii
      $s3 = "ustrreffix.dll" fullword ascii
      $s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 320KB and all of them
}