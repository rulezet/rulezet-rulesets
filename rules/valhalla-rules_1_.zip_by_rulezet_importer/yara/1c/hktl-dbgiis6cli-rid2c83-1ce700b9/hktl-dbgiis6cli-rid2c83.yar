rule HKTL_dbgiis6cli_RID2C83 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dbgiis6cli.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:52:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)" 
      $s5 = "###command:(NO more than 100 bytes!)" 
   condition: 
      all of them
}