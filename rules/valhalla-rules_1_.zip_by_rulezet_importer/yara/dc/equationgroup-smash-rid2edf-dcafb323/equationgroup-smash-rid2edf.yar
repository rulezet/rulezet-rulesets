rule EquationGroup_smash_RID2EDF : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file smash"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:33:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1dc94b46aaff06d65a3bf724c8701e5f095c1c9c131b65b2f667e11b1f0129a6"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "T=<target IP> [O=<port>] Y=<target type>" fullword ascii
      $x2 = "no command given!! bailing..." fullword ascii
      $x3 = "no port. assuming 22..." fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}