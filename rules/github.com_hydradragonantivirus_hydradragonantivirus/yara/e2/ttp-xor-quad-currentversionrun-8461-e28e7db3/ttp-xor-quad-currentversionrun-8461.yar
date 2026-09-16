rule TTP_XOR_QUAD_CurrentVersionRun_8461 {
  strings:
    $key_8461 = { d7 0e [2] f3 00 [2] d8 2c [2] f6 0e [2] e2 15 [2] ed 0f [2] f3 12 [2] f1 13 [2] ea 15 [2] f6 12 [2] ea 3d }

  condition:
    any of them
}