rule Webshell_connectback2_pl_RID308E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file connectback2.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   " 
      $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel" 
      $s2 = "ConnectBack Backdoor" 
   condition: 
      1 of them
}