rule Webshell_QueryDong_spyjsp2010_t00ls_RID3421 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:17:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')" 
      $s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\"" 
   condition: 
      all of them
}