rule Webshell_Txt_aspx1_RID2E32 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:04:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[" 
      $s1 = "],\"unsafe\");%>" fullword ascii
   condition: 
      filesize < 150 and all of them
}