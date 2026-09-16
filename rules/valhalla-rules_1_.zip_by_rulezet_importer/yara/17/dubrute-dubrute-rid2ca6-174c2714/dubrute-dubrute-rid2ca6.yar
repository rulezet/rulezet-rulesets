rule DUBrute_DUBrute_RID2CA6 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file DUBrute.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:58:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
      $s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
      $s3 = "Create %d IP@Loginl;Password" fullword ascii
      $s4 = "UBrute.com" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1020KB and all of them
}