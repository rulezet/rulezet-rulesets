rule TTP_XOR_QUAD_CurrentVersionRun_d889 {
  strings:
    $key_d889 = { 8b e6 [2] af e8 [2] 84 c4 [2] aa e6 [2] be fd [2] b1 e7 [2] af fa [2] ad fb [2] b6 fd [2] aa fa [2] b6 d5 }

  condition:
    any of them
}