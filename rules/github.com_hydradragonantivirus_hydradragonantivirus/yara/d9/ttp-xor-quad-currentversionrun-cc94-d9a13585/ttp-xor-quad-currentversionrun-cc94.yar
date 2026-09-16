rule TTP_XOR_QUAD_CurrentVersionRun_cc94 {
  strings:
    $key_cc94 = { 9f fb [2] bb f5 [2] 90 d9 [2] be fb [2] aa e0 [2] a5 fa [2] bb e7 [2] b9 e6 [2] a2 e0 [2] be e7 [2] a2 c8 }

  condition:
    any of them
}