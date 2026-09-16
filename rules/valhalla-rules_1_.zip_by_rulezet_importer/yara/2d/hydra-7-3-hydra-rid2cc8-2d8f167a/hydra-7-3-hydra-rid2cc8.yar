rule hydra_7_3_hydra_RID2CC8 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file hydra.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:03:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
      $s2 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE" ascii
      $s3 = "cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com" fullword ascii
      $s4 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
      $s5 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of them
}