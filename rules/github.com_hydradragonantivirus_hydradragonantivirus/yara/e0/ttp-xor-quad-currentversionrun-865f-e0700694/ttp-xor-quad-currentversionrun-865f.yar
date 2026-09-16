rule TTP_XOR_QUAD_CurrentVersionRun_865f {
  strings:
    $key_865f = { d5 30 [2] f1 3e [2] da 12 [2] f4 30 [2] e0 2b [2] ef 31 [2] f1 2c [2] f3 2d [2] e8 2b [2] f4 2c [2] e8 03 }

  condition:
    any of them
}