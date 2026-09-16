rule TTP_XOR_QUAD_CurrentVersionRun_8b33 {
  strings:
    $key_8b33 = { d8 5c [2] fc 52 [2] d7 7e [2] f9 5c [2] ed 47 [2] e2 5d [2] fc 40 [2] fe 41 [2] e5 47 [2] f9 40 [2] e5 6f }

  condition:
    any of them
}