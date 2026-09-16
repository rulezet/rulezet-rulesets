rule CN_Honker_Webshell_portRecall_jsp2_RID3452 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:25:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii
      $s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii
      $s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii
   condition: 
      filesize < 23KB and all of them
}