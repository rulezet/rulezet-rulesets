rule WebShell_toolaspshell_RID2FA0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file toolaspshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:05:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef" 
      $s1 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
      $s2 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
   condition: 
      2 of them
}