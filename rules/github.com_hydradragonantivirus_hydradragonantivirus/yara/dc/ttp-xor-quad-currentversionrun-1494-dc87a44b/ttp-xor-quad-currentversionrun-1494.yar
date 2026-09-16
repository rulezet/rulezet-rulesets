rule TTP_XOR_QUAD_CurrentVersionRun_1494 {
  strings:
    $key_1494 = { 47 fb [2] 63 f5 [2] 48 d9 [2] 66 fb [2] 72 e0 [2] 7d fa [2] 63 e7 [2] 61 e6 [2] 7a e0 [2] 66 e7 [2] 7a c8 }

  condition:
    any of them
}