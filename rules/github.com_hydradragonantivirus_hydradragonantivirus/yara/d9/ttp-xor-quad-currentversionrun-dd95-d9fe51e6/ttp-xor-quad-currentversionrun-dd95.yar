rule TTP_XOR_QUAD_CurrentVersionRun_dd95 {
  strings:
    $key_dd95 = { 8e fa [2] aa f4 [2] 81 d8 [2] af fa [2] bb e1 [2] b4 fb [2] aa e6 [2] a8 e7 [2] b3 e1 [2] af e6 [2] b3 c9 }

  condition:
    any of them
}