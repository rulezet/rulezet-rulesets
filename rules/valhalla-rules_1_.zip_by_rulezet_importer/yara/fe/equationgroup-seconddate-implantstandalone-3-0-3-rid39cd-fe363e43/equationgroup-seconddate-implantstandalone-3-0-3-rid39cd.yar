rule EquationGroup_seconddate_ImplantStandalone_3_0_3_RID39CD : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 19:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d687aa644095c81b53a69c206eb8d6bdfe429d7adc2a57d87baf8ff8d4233511"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
      $s2 = "G8HcJ HcF LcF0LcN" fullword ascii
      $s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 1000KB and all of them )
}