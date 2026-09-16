rule CN_Honker_Webshell_Serv_U_2_admin_by_lake2_RID3711 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U 2 admin by lake2.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:22:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii
      $s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii
      $s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii
      $s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii
   condition: 
      filesize < 17KB and 2 of them
}