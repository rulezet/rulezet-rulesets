rule Webshell_ASP_zehir_RID2E0B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zehir.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&" 
   condition: 
      all of them
}