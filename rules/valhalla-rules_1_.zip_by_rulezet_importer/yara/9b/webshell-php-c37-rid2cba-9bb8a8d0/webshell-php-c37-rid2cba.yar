rule Webshell_PHP_c37_RID2CBA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file c37.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:01:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj')," 
      $s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE]," 
   condition: 
      all of them
}