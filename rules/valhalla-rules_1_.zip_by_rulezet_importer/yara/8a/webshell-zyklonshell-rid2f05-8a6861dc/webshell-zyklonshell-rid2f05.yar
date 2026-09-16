rule WebShell_ZyklonShell_RID2F05 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file ZyklonShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:39:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
      $s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
      $s2 = "<TITLE>404 Not Found</TITLE>" fullword
      $s3 = "<H1>Not Found</H1>" fullword
   condition: 
      all of them
}