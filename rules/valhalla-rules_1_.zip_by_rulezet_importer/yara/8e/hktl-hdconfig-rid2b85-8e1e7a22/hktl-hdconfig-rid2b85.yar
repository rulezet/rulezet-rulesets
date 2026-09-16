rule HKTL_HDConfig_RID2B85 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file HDConfig.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:10:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "An encryption key is derived from the password hash. " 
      $s3 = "A hash object has been created. " 
      $s4 = "Error during CryptCreateHash!" 
      $s5 = "A new key container has been created." 
      $s6 = "The password has been added to the hash. " 
   condition: 
      all of them
}