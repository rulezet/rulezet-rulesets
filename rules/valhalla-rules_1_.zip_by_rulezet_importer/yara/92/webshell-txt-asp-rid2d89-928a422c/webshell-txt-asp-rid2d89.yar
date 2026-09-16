rule Webshell_Txt_asp_RID2D89 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file asp.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
      $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 100KB and all of them
}