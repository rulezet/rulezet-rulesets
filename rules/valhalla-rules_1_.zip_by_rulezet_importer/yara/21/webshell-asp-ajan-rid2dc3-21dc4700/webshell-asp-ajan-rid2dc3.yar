rule Webshell_asp_Ajan_RID2DC3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:45:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate" 
   condition: 
      all of them
}