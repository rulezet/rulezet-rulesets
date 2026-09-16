rule Webshell_Antichat_Shell_v1_3_2_RID3252 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Antichat Shell v1.3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:00:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m" 
   condition: 
      all of them
}