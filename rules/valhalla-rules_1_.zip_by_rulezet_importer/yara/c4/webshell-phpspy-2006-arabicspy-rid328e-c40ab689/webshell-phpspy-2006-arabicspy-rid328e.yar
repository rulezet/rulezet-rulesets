rule Webshell_phpspy_2006_arabicspy_RID328E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:10:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
      hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
      hash3 = "40a1f840111996ff7200d18968e42cfe"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$this -> addFile($content, $filename);" fullword
      $s3 = "function addFile($data, $name, $time = 0) {" fullword
      $s8 = "function unix2DosTime($unixtime = 0) {" fullword
      $s9 = "foreach($filelist as $filename){" fullword
   condition: 
      all of them
}