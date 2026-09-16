rule Webshell_aspydrv_asp_RID2F52 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file aspydrv.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:52:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))" 
      $s1 = "password" 
      $s2 = "session(\"shagman\")=" 
   condition: 
      2 of them
}