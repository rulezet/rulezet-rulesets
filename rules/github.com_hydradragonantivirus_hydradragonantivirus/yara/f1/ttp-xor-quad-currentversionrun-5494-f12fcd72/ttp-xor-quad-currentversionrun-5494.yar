rule TTP_XOR_QUAD_CurrentVersionRun_5494 {
  strings:
    $key_5494 = { 07 fb [2] 23 f5 [2] 08 d9 [2] 26 fb [2] 32 e0 [2] 3d fa [2] 23 e7 [2] 21 e6 [2] 3a e0 [2] 26 e7 [2] 3a c8 }

  condition:
    any of them
}