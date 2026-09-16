rule Webshell_2008_2009lite_2009mssql_RID31A2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:30:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3f4d454d27ecc0013e783ed921eeecde"
      hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');" 
      $s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all" 
   condition: 
      all of them
}