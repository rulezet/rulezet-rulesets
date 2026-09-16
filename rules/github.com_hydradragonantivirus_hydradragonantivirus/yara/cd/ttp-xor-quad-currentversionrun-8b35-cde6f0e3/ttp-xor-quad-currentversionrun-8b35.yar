rule TTP_XOR_QUAD_CurrentVersionRun_8b35 {
  strings:
    $key_8b35 = { d8 5a [2] fc 54 [2] d7 78 [2] f9 5a [2] ed 41 [2] e2 5b [2] fc 46 [2] fe 47 [2] e5 41 [2] f9 46 [2] e5 69 }

  condition:
    any of them
}