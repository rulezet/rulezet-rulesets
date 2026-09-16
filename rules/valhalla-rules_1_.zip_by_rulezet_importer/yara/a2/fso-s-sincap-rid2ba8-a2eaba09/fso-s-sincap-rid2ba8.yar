rule FSO_s_sincap_RID2BA8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file sincap.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">" 
      $s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin=" 
   condition: 
      all of them
}