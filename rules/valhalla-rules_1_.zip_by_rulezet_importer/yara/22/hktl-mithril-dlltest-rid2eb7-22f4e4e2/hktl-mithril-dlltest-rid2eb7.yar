rule HKTL_Mithril_dllTest_RID2EB7 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:26:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "please enter the password:" 
      $s3 = "\\dllTest.pdb" 
   condition: 
      all of them
}