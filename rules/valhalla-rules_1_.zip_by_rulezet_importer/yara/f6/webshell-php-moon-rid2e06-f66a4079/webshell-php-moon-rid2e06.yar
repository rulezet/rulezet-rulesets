rule Webshell_php_moon_RID2E06 : DEMO SCRIPT T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file moon.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo '<option value=\"create function backshell returns string soname" 
      $s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\"" 
      $s8 = "echo '<option value=\"select cmdshell(\\'net user " 
   condition: 
      2 of them
}