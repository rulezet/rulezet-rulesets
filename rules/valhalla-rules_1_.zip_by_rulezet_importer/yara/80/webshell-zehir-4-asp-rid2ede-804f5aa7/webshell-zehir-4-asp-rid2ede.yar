rule Webshell_Zehir_4_asp_RID2EDE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Zehir 4.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time=" 
      $s4 = "<input type=submit value=\"Test Et!\" onclick=\"" 
   condition: 
      1 of them
}