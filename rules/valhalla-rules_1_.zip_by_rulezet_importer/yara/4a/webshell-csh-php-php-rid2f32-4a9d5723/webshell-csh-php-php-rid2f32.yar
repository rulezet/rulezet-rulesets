rule Webshell_csh_php_php_RID2F32 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file csh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ".::[c0derz]::. web-shell" 
      $s1 = "http://c0derz.org.ua" 
      $s2 = "vint21h@c0derz.org.ua" 
      $s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root" 
   condition: 
      1 of them
}