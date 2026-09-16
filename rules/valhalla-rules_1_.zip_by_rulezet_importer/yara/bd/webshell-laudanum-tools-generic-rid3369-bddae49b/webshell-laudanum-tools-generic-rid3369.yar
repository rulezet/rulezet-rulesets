rule Webshell_Laudanum_Tools_Generic_RID3369 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 14:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
      hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
      hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "***  laudanum@secureideas.net" fullword ascii
      $s2 = "*** Laudanum Project" fullword ascii
   condition: 
      filesize < 60KB and all of them
}