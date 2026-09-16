rule Webshell_ASP_zehir4_RID2E3F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/" 
   condition: 
      all of them
}