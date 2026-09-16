rule TTP_XOR_QUAD_CurrentVersionRun_8143 {
  strings:
    $key_8143 = { d2 2c [2] f6 22 [2] dd 0e [2] f3 2c [2] e7 37 [2] e8 2d [2] f6 30 [2] f4 31 [2] ef 37 [2] f3 30 [2] ef 1f }

  condition:
    any of them
}