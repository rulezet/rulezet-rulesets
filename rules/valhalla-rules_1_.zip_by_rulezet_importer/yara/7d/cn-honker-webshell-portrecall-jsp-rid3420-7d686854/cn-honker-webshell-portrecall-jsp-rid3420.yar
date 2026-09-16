rule CN_Honker_Webshell_portRecall_jsp_RID3420 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:17:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii
   condition: 
      filesize < 1KB and all of them
}