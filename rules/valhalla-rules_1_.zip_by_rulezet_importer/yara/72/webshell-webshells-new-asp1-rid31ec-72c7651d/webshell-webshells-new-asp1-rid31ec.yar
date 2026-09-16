rule Webshell_webshells_new_asp1_RID31EC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file asp1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:43:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
      $s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
   condition: 
      1 of them
}