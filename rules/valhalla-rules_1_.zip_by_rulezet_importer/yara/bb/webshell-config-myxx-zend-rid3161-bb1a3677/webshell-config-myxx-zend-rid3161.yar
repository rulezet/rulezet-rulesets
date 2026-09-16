rule Webshell_config_myxx_zend_RID3161 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:20:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e0354099bee243702eb11df8d0e046df"
      hash2 = "591ca89a25f06cf01e4345f98a22845c"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');" 
   condition: 
      all of them
}