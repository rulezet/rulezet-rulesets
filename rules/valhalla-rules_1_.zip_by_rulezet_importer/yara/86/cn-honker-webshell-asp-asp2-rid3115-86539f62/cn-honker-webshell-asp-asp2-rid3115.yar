rule CN_Honker_Webshell_ASP_asp2_RID3115 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
      $s2 = "webshell</font> <font color=#00FF00>" fullword ascii
      $s3 = "Userpwd = \"admin\"   'User Password" fullword ascii
   condition: 
      filesize < 10KB and all of them
}