rule EquationGroup_ewok {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"
      id = "379c233f-86f8-5116-a15c-8a80b27daea6"
   strings:
      $x1 = "Example: ewok -t target public" fullword ascii
      $x2 = "Usage:  cleaner host community fake_prog" fullword ascii
      $x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
      $x4 = "--- ewok version" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and 1 of them )
}