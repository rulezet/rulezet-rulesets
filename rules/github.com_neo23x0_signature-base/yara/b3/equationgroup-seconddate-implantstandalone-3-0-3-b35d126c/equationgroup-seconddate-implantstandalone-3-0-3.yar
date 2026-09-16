rule EquationGroup_seconddate_ImplantStandalone_3_0_3 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "d687aa644095c81b53a69c206eb8d6bdfe429d7adc2a57d87baf8ff8d4233511"
      id = "08b1aa88-8731-51db-b659-96147f509bcd"
   strings:
      $s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
      $s2 = "G8HcJ HcF LcF0LcN" fullword ascii
      $s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and all of them )
}