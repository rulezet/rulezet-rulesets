rule Webshell_HYTop_DevPack_2005_RID309D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:47:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")" 
      $s8 = "scrollbar-darkshadow-color:#9C9CD3;" 
      $s9 = "scrollbar-face-color:#E4E4F3;" 
   condition: 
      all of them
}