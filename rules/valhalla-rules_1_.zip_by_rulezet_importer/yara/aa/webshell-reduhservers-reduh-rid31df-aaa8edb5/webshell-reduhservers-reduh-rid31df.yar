rule Webshell_reDuhServers_reDuh_RID31DF : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:41:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
      $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii
      $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
      $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
   condition: 
      filesize < 116KB and all of them
}