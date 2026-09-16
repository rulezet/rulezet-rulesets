rule TTP_XOR_QUAD_CurrentVersionRun_8154 {
  strings:
    $key_8154 = { d2 3b [2] f6 35 [2] dd 19 [2] f3 3b [2] e7 20 [2] e8 3a [2] f6 27 [2] f4 26 [2] ef 20 [2] f3 27 [2] ef 08 }

  condition:
    any of them
}