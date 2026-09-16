rule CN_Honker_Webshell_JSPMSSQL_RID30D9 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file JSPMSSQL.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:57:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii
      $s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii
   condition: 
      filesize < 35KB and all of them
}