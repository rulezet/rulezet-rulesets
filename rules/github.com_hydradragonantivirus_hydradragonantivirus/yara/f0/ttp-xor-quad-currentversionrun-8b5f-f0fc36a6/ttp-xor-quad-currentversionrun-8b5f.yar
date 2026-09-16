rule TTP_XOR_QUAD_CurrentVersionRun_8b5f {
  strings:
    $key_8b5f = { d8 30 [2] fc 3e [2] d7 12 [2] f9 30 [2] ed 2b [2] e2 31 [2] fc 2c [2] fe 2d [2] e5 2b [2] f9 2c [2] e5 03 }

  condition:
    any of them
}