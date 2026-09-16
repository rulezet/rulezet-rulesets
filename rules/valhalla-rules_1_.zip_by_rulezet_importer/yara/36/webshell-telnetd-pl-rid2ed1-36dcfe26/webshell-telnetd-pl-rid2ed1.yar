rule Webshell_telnetd_pl_RID2ED1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnetd.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:30:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "0ldW0lf" fullword
      $s1 = "However you are lucky :P" 
      $s2 = "I'm FuCKeD" 
      $s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#" 
      $s4 = "atrix@irc.brasnet.org" 
   condition: 
      1 of them
}