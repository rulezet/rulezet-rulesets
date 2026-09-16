rule Webshell_acid_AntiSecShell_3_RID31C7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell Acid"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 13:37:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";" fullword ascii
      $s1 = "if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}" fullword ascii
   condition: 
      filesize < 900KB and all of them
}