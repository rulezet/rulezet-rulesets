rule TTP_XOR_QUAD_CurrentVersionRun_8b15 {
  strings:
    $key_8b15 = { d8 7a [2] fc 74 [2] d7 58 [2] f9 7a [2] ed 61 [2] e2 7b [2] fc 66 [2] fe 67 [2] e5 61 [2] f9 66 [2] e5 49 }

  condition:
    any of them
}