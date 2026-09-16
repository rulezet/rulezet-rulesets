rule TTP_XOR_QUAD_CurrentVersionRun_1294 {
  strings:
    $key_1294 = { 41 fb [2] 65 f5 [2] 4e d9 [2] 60 fb [2] 74 e0 [2] 7b fa [2] 65 e7 [2] 67 e6 [2] 7c e0 [2] 60 e7 [2] 7c c8 }

  condition:
    any of them
}