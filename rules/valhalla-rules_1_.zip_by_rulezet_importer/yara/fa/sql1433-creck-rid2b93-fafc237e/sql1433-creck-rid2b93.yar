rule sql1433_creck_RID2B93 : APT CHINA DEMO FILE SCRIPT {
   meta:
      description = "Chinese Hacktool Set - file creck.bat"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:12:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "start anhao3.exe -i S.txt -p  pass3.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii
      $s1 = "start anhao1.exe -i S.txt -p  pass1.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii
      $s2 = "start anhao2.exe -i S.txt -p  pass2.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7473 and filesize < 1KB and 1 of them
}