rule WEBSHELL_ASP_Embedded_Mar21_1_RID3085 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-05 12:43:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<script runat=\"server\">" nocase
      $s2 = "new System.IO.StreamWriter(Request.Form[" 
      $s3 = ".Write(Request.Form[" 
   condition: 
      filesize < 100KB and all of them
}