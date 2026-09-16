rule EquationGroup_scripme {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file scripme"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a1adf1c1caad96e7b7fd92cbf419c4cfa13214e66497c9e46ec274a487cd098a"
      id = "a2c5cd8b-c104-57d9-9ce2-a0b9a8dd9288"
   strings:
      $x1 = "running \\\"tcpdump -n -n\\\", on the environment variable \\$INTERFACE, scripted" fullword ascii
      $x2 = "Cannot read $opetc/scripme.override -- are you root?" ascii
      $x3 = "$ENV{EXPLOIT_SCRIPME}" ascii
      $x4 = "$opetc/scripme.override" ascii
   condition:
      ( filesize < 30KB and 1 of them )
}