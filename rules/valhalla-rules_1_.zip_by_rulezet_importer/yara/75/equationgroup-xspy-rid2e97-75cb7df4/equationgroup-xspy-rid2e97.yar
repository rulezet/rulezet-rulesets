rule EquationGroup_xspy_RID2E97 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 60KB and all of them )
}