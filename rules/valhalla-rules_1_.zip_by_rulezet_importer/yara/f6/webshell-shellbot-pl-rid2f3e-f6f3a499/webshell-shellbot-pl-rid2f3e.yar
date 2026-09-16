rule Webshell_shellbot_pl_RID2F3E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shellbot.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:48:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ShellBOT" 
      $s1 = "PacktsGr0up" 
      $s2 = "CoRpOrAtIoN" 
      $s3 = "# Servidor de irc que vai ser usado " 
      $s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)" 
   condition: 
      2 of them
}