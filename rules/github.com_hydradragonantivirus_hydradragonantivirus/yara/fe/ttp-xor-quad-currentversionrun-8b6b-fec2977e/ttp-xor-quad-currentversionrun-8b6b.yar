rule TTP_XOR_QUAD_CurrentVersionRun_8b6b {
  strings:
    $key_8b6b = { d8 04 [2] fc 0a [2] d7 26 [2] f9 04 [2] ed 1f [2] e2 05 [2] fc 18 [2] fe 19 [2] e5 1f [2] f9 18 [2] e5 37 }

  condition:
    any of them
}