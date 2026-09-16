rule Webshell_c99_4_RID2C0E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects C99 Webshell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 09:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      hash3 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));" fullword ascii
      $s2 = "displaysecinfo(\"RAM\",myshellexec(\"free -m\"));" fullword ascii
      $s3 = "displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));" fullword ascii
      $s4 = "$ret = myshellexec($handler);" fullword ascii
      $s5 = "if (posix_kill($pid,$sig)) {echo \"OK.\";}" fullword ascii
   condition: 
      filesize < 900KB and 1 of them
}