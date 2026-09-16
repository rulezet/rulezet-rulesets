rule CN_Honker_Webshell_JSP_jsp_RID30F5 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp.html"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:02:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii
      $s2 = "<font color=red>www.i0day.com  By:" fullword ascii
   condition: 
      filesize < 3KB and all of them
}