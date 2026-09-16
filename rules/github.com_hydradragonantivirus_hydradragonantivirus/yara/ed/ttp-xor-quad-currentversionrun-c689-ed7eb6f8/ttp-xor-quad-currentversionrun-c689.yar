rule TTP_XOR_QUAD_CurrentVersionRun_c689 {
  strings:
    $key_c689 = { 95 e6 [2] b1 e8 [2] 9a c4 [2] b4 e6 [2] a0 fd [2] af e7 [2] b1 fa [2] b3 fb [2] a8 fd [2] b4 fa [2] a8 d5 }

  condition:
    any of them
}