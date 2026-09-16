rule TTP_XOR_QUAD_CurrentVersionRun_d694 {
  strings:
    $key_d694 = { 85 fb [2] a1 f5 [2] 8a d9 [2] a4 fb [2] b0 e0 [2] bf fa [2] a1 e7 [2] a3 e6 [2] b8 e0 [2] a4 e7 [2] b8 c8 }

  condition:
    any of them
}