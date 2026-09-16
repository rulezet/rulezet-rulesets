rule PEiD_00039_ActiveMARK_TM_ {
  meta:
    description = "[ActiveMARK[TM]"
    ep_only     = "true"

  strings:
    $a = { 79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25 }

  condition:
    $a
}