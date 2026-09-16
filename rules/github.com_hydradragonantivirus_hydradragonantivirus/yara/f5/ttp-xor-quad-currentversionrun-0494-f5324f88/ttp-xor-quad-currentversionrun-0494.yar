rule TTP_XOR_QUAD_CurrentVersionRun_0494 {
  strings:
    $key_0494 = { 57 fb [2] 73 f5 [2] 58 d9 [2] 76 fb [2] 62 e0 [2] 6d fa [2] 73 e7 [2] 71 e6 [2] 6a e0 [2] 76 e7 [2] 6a c8 }

  condition:
    any of them
}