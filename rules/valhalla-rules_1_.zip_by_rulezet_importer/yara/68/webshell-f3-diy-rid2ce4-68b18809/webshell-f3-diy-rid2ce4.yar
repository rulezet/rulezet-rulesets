rule Webshell_f3_diy_RID2CE4 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file diy.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:08:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
      $s5 = ".black {" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 10KB and all of them
}