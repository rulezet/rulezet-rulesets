rule TTP_XOR_QUAD_CurrentVersionRun_8159 {
  strings:
    $key_8159 = { d2 36 [2] f6 38 [2] dd 14 [2] f3 36 [2] e7 2d [2] e8 37 [2] f6 2a [2] f4 2b [2] ef 2d [2] f3 2a [2] ef 05 }

  condition:
    any of them
}