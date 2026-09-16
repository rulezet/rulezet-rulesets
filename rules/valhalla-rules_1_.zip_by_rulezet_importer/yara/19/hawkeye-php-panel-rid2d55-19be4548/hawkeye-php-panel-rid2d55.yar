rule HawkEye_PHP_Panel_RID2D55 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects HawkEye Keyloggers PHP Panel"
      author = "Florian Roth"
      reference = "-"
      date = "2014-12-14 10:27:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$fname = $_GET['fname'];" ascii fullword
      $s1 = "$data = $_GET['data'];" ascii fullword
      $s2 = "unlink($fname);" ascii fullword
      $s3 = "echo \"Success\";" fullword ascii
   condition: 
      all of ( $s* ) and filesize < 600
}