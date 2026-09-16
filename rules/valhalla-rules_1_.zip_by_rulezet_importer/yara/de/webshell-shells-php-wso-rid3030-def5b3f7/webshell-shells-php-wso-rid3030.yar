rule Webshell_shells_PHP_wso_RID3030 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file wso.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:29:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi" 
      $s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos" 
   condition: 
      1 of them
}