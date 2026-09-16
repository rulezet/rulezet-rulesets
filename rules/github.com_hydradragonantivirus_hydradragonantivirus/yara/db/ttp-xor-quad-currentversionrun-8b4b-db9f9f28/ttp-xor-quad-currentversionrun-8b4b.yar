rule TTP_XOR_QUAD_CurrentVersionRun_8b4b {
  strings:
    $key_8b4b = { d8 24 [2] fc 2a [2] d7 06 [2] f9 24 [2] ed 3f [2] e2 25 [2] fc 38 [2] fe 39 [2] e5 3f [2] f9 38 [2] e5 17 }

  condition:
    any of them
}