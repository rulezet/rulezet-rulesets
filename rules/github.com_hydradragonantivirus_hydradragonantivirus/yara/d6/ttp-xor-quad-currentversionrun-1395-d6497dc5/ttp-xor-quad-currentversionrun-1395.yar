rule TTP_XOR_QUAD_CurrentVersionRun_1395 {
  strings:
    $key_1395 = { 40 fa [2] 64 f4 [2] 4f d8 [2] 61 fa [2] 75 e1 [2] 7a fb [2] 64 e6 [2] 66 e7 [2] 7d e1 [2] 61 e6 [2] 7d c9 }

  condition:
    any of them
}