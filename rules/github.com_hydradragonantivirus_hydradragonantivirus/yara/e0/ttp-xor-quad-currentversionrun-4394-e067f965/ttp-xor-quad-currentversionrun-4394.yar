rule TTP_XOR_QUAD_CurrentVersionRun_4394 {
  strings:
    $key_4394 = { 10 fb [2] 34 f5 [2] 1f d9 [2] 31 fb [2] 25 e0 [2] 2a fa [2] 34 e7 [2] 36 e6 [2] 2d e0 [2] 31 e7 [2] 2d c8 }

  condition:
    any of them
}