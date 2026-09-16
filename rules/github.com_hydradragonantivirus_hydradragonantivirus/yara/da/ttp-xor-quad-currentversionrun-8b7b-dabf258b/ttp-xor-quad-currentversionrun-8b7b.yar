rule TTP_XOR_QUAD_CurrentVersionRun_8b7b {
  strings:
    $key_8b7b = { d8 14 [2] fc 1a [2] d7 36 [2] f9 14 [2] ed 0f [2] e2 15 [2] fc 08 [2] fe 09 [2] e5 0f [2] f9 08 [2] e5 27 }

  condition:
    any of them
}