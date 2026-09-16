rule Webshell_webshells_new_con2_RID31E9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file con2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:42:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e" 
      $s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n" 
   condition: 
      1 of them
}