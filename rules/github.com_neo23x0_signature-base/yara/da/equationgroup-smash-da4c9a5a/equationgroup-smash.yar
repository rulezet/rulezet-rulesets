rule EquationGroup_smash {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file smash"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1dc94b46aaff06d65a3bf724c8701e5f095c1c9c131b65b2f667e11b1f0129a6"
      id = "9a8cb090-4f47-5674-accb-f233dbb19b71"
   strings:
      $x1 = "T=<target IP> [O=<port>] Y=<target type>" fullword ascii
      $x2 = "no command given!! bailing..." fullword ascii
      $x3 = "no port. assuming 22..." fullword ascii
   condition:
      filesize < 250KB and 1 of them
}