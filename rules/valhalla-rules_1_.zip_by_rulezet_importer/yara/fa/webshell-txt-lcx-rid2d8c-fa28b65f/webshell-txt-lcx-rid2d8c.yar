rule Webshell_Txt_lcx_RID2D8C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file lcx.c"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
      $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
      $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
      $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
      $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
   condition: 
      filesize < 25KB and 2 of them
}