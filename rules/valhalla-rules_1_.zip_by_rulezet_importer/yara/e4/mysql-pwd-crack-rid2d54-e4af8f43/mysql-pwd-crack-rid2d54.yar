rule mysql_pwd_crack_RID2D54 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file mysql_pwd_crack_RID2D54.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:27:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mysql_pwd_crack_RID2D54 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
      $s2 = "Successfully --> username %s password %s " fullword ascii
      $s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
      $s4 = "-a automode  automatic crack the mysql password " fullword ascii
      $s5 = "mysql_pwd_crack_RID2D54 127.0.0.1 -x 3306 -a" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them
}