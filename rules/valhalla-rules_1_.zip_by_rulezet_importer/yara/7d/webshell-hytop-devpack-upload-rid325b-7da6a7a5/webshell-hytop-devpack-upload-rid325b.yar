rule Webshell_HYTop_DevPack_upload_RID325B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file upload.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:01:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<!-- PageUpload Below -->" 
   condition: 
      all of them
}