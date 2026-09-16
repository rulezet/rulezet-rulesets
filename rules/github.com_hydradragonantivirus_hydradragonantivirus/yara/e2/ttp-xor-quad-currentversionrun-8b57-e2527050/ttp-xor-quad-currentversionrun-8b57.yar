rule TTP_XOR_QUAD_CurrentVersionRun_8b57 {
  strings:
    $key_8b57 = { d8 38 [2] fc 36 [2] d7 1a [2] f9 38 [2] ed 23 [2] e2 39 [2] fc 24 [2] fe 25 [2] e5 23 [2] f9 24 [2] e5 0b }

  condition:
    any of them
}