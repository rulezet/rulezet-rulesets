rule Webshell_uploader_php_php_RID3150 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file uploader.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
      $s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
      $s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
   condition: 
      2 of them
}