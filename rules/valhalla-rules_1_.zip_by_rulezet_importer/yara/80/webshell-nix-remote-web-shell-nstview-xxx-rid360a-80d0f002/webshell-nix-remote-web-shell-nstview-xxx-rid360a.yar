rule Webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx_RID360A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:38:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4745d510fed4378e4b1730f56f25e569"
      hash2 = "f3ca29b7999643507081caab926e2e74"
      hash3 = "46a18979750fa458a04343cf58faa9bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "BODY, TD, TR {" fullword
      $s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
      $s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
   condition: 
      2 of them
}