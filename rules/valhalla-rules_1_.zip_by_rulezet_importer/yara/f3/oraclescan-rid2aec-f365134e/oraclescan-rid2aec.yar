rule OracleScan_RID2AEC : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file OracleScan_RID2AEC.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:25:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
      $s2 = "\\Borland\\Delphi\\RTL" ascii
      $s3 = "USER_NAME" ascii
      $s4 = "FROMWWHERE" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}