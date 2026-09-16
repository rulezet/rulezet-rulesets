rule Webshell_Crystal_php_nshell_RID3214 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a44d82da21438e32d4f514ab35c26b6"
      hash2 = "0c5d227f4aa76785e4760cdcff78a661"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
      $s1 = "$dires = $dires . $directory;" fullword
      $s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
   condition: 
      2 of them
}