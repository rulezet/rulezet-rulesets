rule HKTL_Debug_dllTest_2_RID2E56 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "\\Debug\\dllTest.pdb" 
      $s5 = "--list the services in the computer" 
   condition: 
      all of them
}