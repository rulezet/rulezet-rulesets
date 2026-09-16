rule WebShell_Generic_PHP_7_RID2F20 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:43:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
      hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
      hash3 = "715f17e286416724e90113feab914c707a26d456"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
      $s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
      $s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
      $s4 = "if( $action == \"dumpTable\" )" fullword
   condition: 
      2 of them
}