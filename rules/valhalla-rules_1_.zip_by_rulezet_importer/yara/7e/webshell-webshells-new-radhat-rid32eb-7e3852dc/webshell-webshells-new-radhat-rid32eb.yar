rule Webshell_webshells_new_radhat_RID32EB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file radhat.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:25:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sod=Array(\"D\",\"7\",\"S" 
   condition: 
      all of them
}