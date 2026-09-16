rule Webshell_27_9_acid_c99_locus7s_RID31FA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 13:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
      $s1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii
   condition: 
      filesize < 1711KB and 1 of them
}