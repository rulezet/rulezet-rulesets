rule TTP_XOR_QUAD_CurrentVersionRun_d189 {
  strings:
    $key_d189 = { 82 e6 [2] a6 e8 [2] 8d c4 [2] a3 e6 [2] b7 fd [2] b8 e7 [2] a6 fa [2] a4 fb [2] bf fd [2] a3 fa [2] bf d5 }

  condition:
    any of them
}