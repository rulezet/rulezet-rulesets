rule Webshell_webshells_new_php6_RID31F5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php6.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "array_map(\"asx73ert\",(ar" 
      $s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
      $s4 = "shell.php?qid=zxexp  " fullword
   condition: 
      1 of them
}