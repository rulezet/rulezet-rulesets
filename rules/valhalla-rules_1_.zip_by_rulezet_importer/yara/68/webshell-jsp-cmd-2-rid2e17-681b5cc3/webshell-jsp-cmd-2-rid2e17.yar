rule Webshell_jsp_cmd_2_RID2E17 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file cmd.war"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:59:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cmd.jsp}" fullword ascii
      $s1 = "cmd.jspPK" fullword ascii
      $s2 = "WEB-INF/web.xml" fullword ascii
      $s3 = "WEB-INF/web.xmlPK" fullword ascii
      $s4 = "META-INF/MANIFEST.MF" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 2KB and all of them
}