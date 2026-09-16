rule TTP_XOR_QUAD_CurrentVersionRun_8177 {
  strings:
    $key_8177 = { d2 18 [2] f6 16 [2] dd 3a [2] f3 18 [2] e7 03 [2] e8 19 [2] f6 04 [2] f4 05 [2] ef 03 [2] f3 04 [2] ef 2b }

  condition:
    any of them
}