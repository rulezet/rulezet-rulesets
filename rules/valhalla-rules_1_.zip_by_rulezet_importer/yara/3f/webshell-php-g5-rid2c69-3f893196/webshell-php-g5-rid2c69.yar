rule Webshell_PHP_G5_RID2C69 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file G5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op" 
   condition: 
      all of them
}