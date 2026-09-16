rule TTP_XOR_QUAD_CurrentVersionRun_8164 {
  strings:
    $key_8164 = { d2 0b [2] f6 05 [2] dd 29 [2] f3 0b [2] e7 10 [2] e8 0a [2] f6 17 [2] f4 16 [2] ef 10 [2] f3 17 [2] ef 38 }

  condition:
    any of them
}