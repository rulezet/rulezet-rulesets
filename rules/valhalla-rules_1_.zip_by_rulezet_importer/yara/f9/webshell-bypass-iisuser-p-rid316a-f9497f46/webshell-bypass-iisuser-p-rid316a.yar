rule Webshell_bypass_iisuser_p_RID316A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file bypass-iisuser-p.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:21:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject" 
   condition: 
      all of them
}