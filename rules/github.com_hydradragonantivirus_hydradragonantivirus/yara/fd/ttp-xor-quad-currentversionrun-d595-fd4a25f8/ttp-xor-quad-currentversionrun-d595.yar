rule TTP_XOR_QUAD_CurrentVersionRun_d595 {
  strings:
    $key_d595 = { 86 fa [2] a2 f4 [2] 89 d8 [2] a7 fa [2] b3 e1 [2] bc fb [2] a2 e6 [2] a0 e7 [2] bb e1 [2] a7 e6 [2] bb c9 }

  condition:
    any of them
}