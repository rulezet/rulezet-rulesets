rule TTP_XOR_QUAD_CurrentVersionRun_7495 {
  strings:
    $key_7495 = { 27 fa [2] 03 f4 [2] 28 d8 [2] 06 fa [2] 12 e1 [2] 1d fb [2] 03 e6 [2] 01 e7 [2] 1a e1 [2] 06 e6 [2] 1a c9 }

  condition:
    any of them
}