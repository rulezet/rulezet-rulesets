rule Webshell_asp_dabao_RID2E40 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file dabao.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &" 
      $s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-" 
   condition: 
      all of them
}