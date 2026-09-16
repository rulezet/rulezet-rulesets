rule TTP_XOR_QUAD_CurrentVersionRun_3494 {
  strings:
    $key_3494 = { 67 fb [2] 43 f5 [2] 68 d9 [2] 46 fb [2] 52 e0 [2] 5d fa [2] 43 e7 [2] 41 e6 [2] 5a e0 [2] 46 e7 [2] 5a c8 }

  condition:
    any of them
}