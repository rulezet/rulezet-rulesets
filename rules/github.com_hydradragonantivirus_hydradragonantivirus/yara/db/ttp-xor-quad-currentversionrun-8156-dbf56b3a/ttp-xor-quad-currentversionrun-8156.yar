rule TTP_XOR_QUAD_CurrentVersionRun_8156 {
  strings:
    $key_8156 = { d2 39 [2] f6 37 [2] dd 1b [2] f3 39 [2] e7 22 [2] e8 38 [2] f6 25 [2] f4 24 [2] ef 22 [2] f3 25 [2] ef 0a }

  condition:
    any of them
}