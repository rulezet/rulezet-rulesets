rule WebShell_Uploader_RID2DC2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Uploader.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
   condition: 
      all of them
}