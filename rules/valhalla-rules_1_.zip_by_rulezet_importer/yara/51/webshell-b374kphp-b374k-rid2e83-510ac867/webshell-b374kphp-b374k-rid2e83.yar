rule Webshell_B374kPHP_B374k_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file B374k.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Http://code.google.com/p/b374k-shell" fullword
      $s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'" 
      $s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
      $s4 = "B374k Vip In Beautify Just For Self" fullword
   condition: 
      1 of them
}