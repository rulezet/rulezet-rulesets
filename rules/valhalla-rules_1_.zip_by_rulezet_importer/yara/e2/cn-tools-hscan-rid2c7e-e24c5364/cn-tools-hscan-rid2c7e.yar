rule CN_Tools_hscan_RID2C7E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file hscan.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:51:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
      $s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
      $s3 = "%s -h www.target.com -all" fullword ascii
      $s4 = ".\\report\\%s-%s.html" fullword ascii
      $s5 = ".\\log\\Hscan.log" fullword ascii
      $s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
      $s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
      $s8 = ".\\conf\\mysql_pass.dic" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}