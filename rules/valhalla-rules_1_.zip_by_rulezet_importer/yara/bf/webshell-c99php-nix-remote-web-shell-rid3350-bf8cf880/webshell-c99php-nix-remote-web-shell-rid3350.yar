rule Webshell_c99php_NIX_REMOTE_WEB_SHELL_RID3350 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nixrem.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:42:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
      hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash3 = "f3ca29b7999643507081caab926e2e74"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
      $s1 = "$ret = posix_kill($pid,$sig);" fullword
      $s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
      $s3 = "$i = $nixpasswd;" fullword
   condition: 
      2 of them
}