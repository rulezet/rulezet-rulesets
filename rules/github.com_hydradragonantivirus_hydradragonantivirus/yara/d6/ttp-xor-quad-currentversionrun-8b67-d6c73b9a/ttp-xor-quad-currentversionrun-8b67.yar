rule TTP_XOR_QUAD_CurrentVersionRun_8b67 {
  strings:
    $key_8b67 = { d8 08 [2] fc 06 [2] d7 2a [2] f9 08 [2] ed 13 [2] e2 09 [2] fc 14 [2] fe 15 [2] e5 13 [2] f9 14 [2] e5 3b }

  condition:
    any of them
}