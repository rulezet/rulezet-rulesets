rule ChinaChopper_caidao_RID2E85 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file caidao.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:18:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Pass,Config,n{)" fullword ascii
      $s2 = "phMYSQLZ" fullword ascii
      $s3 = "\\DHLP\\." ascii
      $s4 = "\\dhlp\\." ascii
      $s5 = "SHAutoComple" fullword ascii
      $s6 = "MainFrame" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1077KB and all of them
}