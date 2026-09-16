rule TTP_XOR_QUAD_CurrentVersionRun_864f {
  strings:
    $key_864f = { d5 20 [2] f1 2e [2] da 02 [2] f4 20 [2] e0 3b [2] ef 21 [2] f1 3c [2] f3 3d [2] e8 3b [2] f4 3c [2] e8 13 }

  condition:
    any of them
}