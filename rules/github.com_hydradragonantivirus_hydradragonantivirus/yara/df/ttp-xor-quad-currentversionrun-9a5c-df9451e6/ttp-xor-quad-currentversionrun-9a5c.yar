rule TTP_XOR_QUAD_CurrentVersionRun_9a5c {
  strings:
    $key_9a5c = { c9 33 [2] ed 3d [2] c6 11 [2] e8 33 [2] fc 28 [2] f3 32 [2] ed 2f [2] ef 2e [2] f4 28 [2] e8 2f [2] f4 00 }

  condition:
    any of them
}