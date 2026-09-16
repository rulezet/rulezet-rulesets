rule TTP_XOR_QUAD_CurrentVersionRun_c494 {
  strings:
    $key_c494 = { 97 fb [2] b3 f5 [2] 98 d9 [2] b6 fb [2] a2 e0 [2] ad fa [2] b3 e7 [2] b1 e6 [2] aa e0 [2] b6 e7 [2] aa c8 }

  condition:
    any of them
}