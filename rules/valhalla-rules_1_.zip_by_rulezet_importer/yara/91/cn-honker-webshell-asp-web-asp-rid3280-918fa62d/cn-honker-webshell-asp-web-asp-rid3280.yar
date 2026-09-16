rule CN_Honker_Webshell_ASP_web_asp_RID3280 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file web.asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:07:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii
      $s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
   condition: 
      filesize < 13KB and all of them
}