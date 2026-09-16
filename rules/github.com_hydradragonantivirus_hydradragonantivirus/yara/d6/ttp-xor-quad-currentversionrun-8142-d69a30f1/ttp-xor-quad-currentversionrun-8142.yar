rule TTP_XOR_QUAD_CurrentVersionRun_8142 {
  strings:
    $key_8142 = { d2 2d [2] f6 23 [2] dd 0f [2] f3 2d [2] e7 36 [2] e8 2c [2] f6 31 [2] f4 30 [2] ef 36 [2] f3 31 [2] ef 1e }

  condition:
    any of them
}