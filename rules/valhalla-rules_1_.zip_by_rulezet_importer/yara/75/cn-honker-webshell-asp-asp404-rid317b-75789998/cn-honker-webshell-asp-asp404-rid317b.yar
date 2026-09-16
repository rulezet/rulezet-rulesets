rule CN_Honker_Webshell_ASP_asp404_RID317B : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp404.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:24:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii
      $s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii
      $s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii
   condition: 
      filesize < 113KB and all of them
}