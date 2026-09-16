rule hydra_7_4_1_hydra_RID2D59 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file hydra.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:28:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
      $s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
      $s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
      $s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
      $s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
      $s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}