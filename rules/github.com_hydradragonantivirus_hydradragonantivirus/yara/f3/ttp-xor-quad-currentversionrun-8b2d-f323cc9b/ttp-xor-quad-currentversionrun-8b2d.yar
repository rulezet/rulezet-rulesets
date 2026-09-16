rule TTP_XOR_QUAD_CurrentVersionRun_8b2d {
  strings:
    $key_8b2d = { d8 42 [2] fc 4c [2] d7 60 [2] f9 42 [2] ed 59 [2] e2 43 [2] fc 5e [2] fe 5f [2] e5 59 [2] f9 5e [2] e5 71 }

  condition:
    any of them
}