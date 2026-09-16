rule TTP_XOR_QUAD_CurrentVersionRun_8b36 {
  strings:
    $key_8b36 = { d8 59 [2] fc 57 [2] d7 7b [2] f9 59 [2] ed 42 [2] e2 58 [2] fc 45 [2] fe 44 [2] e5 42 [2] f9 45 [2] e5 6a }

  condition:
    any of them
}