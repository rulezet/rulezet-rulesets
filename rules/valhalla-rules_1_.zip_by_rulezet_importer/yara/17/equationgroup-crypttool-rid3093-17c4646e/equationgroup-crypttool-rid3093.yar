rule EquationGroup_cryptTool_RID3093 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "The encryption key is " fullword ascii
      $s2 = "___tempFile2.out" ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 200KB and all of them )
}