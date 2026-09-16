rule Webshell_php_dodo_zip_RID2FA5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zip.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:06:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x" 
      $s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" 
   condition: 
      all of them
}