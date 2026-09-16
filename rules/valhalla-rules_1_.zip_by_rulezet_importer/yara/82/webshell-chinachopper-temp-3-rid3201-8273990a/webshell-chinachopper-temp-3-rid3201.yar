rule Webshell_ChinaChopper_temp_3_RID3201 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:46:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
      $s1 = "\"],\"unsafe\");%>" ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 150 and all of them
}