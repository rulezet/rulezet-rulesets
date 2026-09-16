rule TTP_XOR_QUAD_CurrentVersionRun_8b09 {
  strings:
    $key_8b09 = { d8 66 [2] fc 68 [2] d7 44 [2] f9 66 [2] ed 7d [2] e2 67 [2] fc 7a [2] fe 7b [2] e5 7d [2] f9 7a [2] e5 55 }

  condition:
    any of them
}