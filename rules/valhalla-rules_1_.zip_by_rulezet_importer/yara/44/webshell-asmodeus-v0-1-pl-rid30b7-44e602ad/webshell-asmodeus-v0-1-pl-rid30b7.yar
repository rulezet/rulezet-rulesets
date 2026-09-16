rule Webshell_Asmodeus_v0_1_pl_RID30B7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Asmodeus v0.1.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "[url=http://www.governmentsecurity.org" 
      $s1 = "perl asmodeus.pl client 6666 127.0.0.1" 
      $s2 = "print \"Asmodeus Perl Remote Shell" 
      $s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword
   condition: 
      2 of them
}