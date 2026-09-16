rule Webshell_nst_php_cybershell_RID322E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:54:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef8828e0bc0641a655de3932199c0527"
      hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
      hash3 = "4745d510fed4378e4b1730f56f25e569"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@$rto=$_POST['rto'];" fullword
      $s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
      $s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
   condition: 
      2 of them
}