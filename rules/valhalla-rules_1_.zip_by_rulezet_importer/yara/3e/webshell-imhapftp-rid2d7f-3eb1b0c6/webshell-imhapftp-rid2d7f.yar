rule Webshell_iMHaPFtp_RID2D7F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file iMHaPFtp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">" 
   condition: 
      all of them
}