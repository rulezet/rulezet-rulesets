rule WebShell_Sincap_1_0_RID2E03 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Sincap 1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
      $s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
      $s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
      $s12 = "while (($ekinci=readdir ($sedat))){" fullword
      $s19 = "$deger2= \"$ich[$tampon4]\";" fullword
   condition: 
      2 of them
}