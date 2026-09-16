rule CN_Honker_Webshell_Serv_U_by_Goldsun_RID3525 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U_by_Goldsun.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii
      $s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
      $s3 = "127.0.0.1:<%=port%>," fullword ascii
      $s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii
   condition: 
      filesize < 30KB and 2 of them
}