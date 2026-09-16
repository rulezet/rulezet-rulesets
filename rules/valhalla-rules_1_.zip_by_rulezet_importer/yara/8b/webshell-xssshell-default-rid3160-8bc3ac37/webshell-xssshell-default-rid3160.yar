rule Webshell_xssshell_default_RID3160 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file default.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")" 
   condition: 
      all of them
}