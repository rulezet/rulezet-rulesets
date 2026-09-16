rule MarathonTool_2_RID2C7A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file MarathonTool.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:50:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
      $s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
      $s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}