rule Webshell_asp_ice_RID2D7A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:33:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC" 
   condition: 
      all of them
}