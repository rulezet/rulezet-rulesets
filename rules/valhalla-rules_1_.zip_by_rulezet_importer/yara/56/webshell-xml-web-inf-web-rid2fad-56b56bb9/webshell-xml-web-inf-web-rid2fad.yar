rule Webshell_XML_WEB_INF_web_RID2FAD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file web.xml"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 12:07:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<servlet-name>Command</servlet-name>" fullword ascii
      $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
   condition: 
      filesize < 1KB and all of them
}