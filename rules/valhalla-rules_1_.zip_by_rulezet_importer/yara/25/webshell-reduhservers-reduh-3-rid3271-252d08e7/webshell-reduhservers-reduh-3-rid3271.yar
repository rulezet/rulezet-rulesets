rule Webshell_reDuhServers_reDuh_3_RID3271 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:05:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
      $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
      $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
      $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
   condition: 
      filesize < 40KB and all of them
}