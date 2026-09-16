rule Webshell_HYTop_DevPack_config_RID324C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file config.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "const adminPassword=\"" 
      $s2 = "const userPassword=\"" 
      $s3 = "const mVersion=" 
   condition: 
      all of them
}