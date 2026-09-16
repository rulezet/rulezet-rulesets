rule TTP_XOR_QUAD_CurrentVersionRun_8b07 {
  strings:
    $key_8b07 = { d8 68 [2] fc 66 [2] d7 4a [2] f9 68 [2] ed 73 [2] e2 69 [2] fc 74 [2] fe 75 [2] e5 73 [2] f9 74 [2] e5 5b }

  condition:
    any of them
}