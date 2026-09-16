rule TTP_XOR_QUAD_CurrentVersionRun_cc95 {
  strings:
    $key_cc95 = { 9f fa [2] bb f4 [2] 90 d8 [2] be fa [2] aa e1 [2] a5 fb [2] bb e6 [2] b9 e7 [2] a2 e1 [2] be e6 [2] a2 c9 }

  condition:
    any of them
}