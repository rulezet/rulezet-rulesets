rule mswin_check_lm_group_RID2F60 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file mswin_check_lm_group_RID2F60.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-03-15"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
      $s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
      $s3 = "-D    default user Domain" fullword ascii
      $fp1 = "Panda Security S.L." ascii wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 380KB and all of ( $s* ) and not 1 of ( $fp* )
}