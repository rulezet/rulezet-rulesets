rule HKTL_PasswordReminder_RID2F2C : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PasswordReminder.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "The encoded password is found at 0x%8.8lx and has a length of %d." 
   condition: 
      all of them
}