rule Webshell_c99shell_v1_0_SsEs_RID3105 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
   condition: 
      1 of them
}