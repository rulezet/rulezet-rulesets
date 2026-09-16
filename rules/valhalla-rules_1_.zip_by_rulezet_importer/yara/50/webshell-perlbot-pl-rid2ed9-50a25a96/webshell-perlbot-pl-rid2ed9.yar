rule Webshell_perlbot_pl_RID2ED9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file perlbot.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")" 
      $s1 = "#Acesso a Shel - 1 ON 0 OFF" 
   condition: 
      1 of them
}