rule Lazagne_PW_Dumper_RID2DA5 : DEMO HKTL T1003 {
   meta:
      description = "Detects Lazagne PW Dumper"
      author = "Markus Neis, Florian Roth"
      reference = "https://github.com/AlessandroZ/LaZagne/releases/"
      date = "2018-03-22 10:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Crypto.Hash" fullword ascii
      $s2 = "laZagne" fullword ascii
      $s3 = "impacket.winregistry" fullword ascii
   condition: 
      3 of them
}