rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version_RID3A6D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 19:46:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
      $s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'." 
      $s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
   condition: 
      1 of them
}