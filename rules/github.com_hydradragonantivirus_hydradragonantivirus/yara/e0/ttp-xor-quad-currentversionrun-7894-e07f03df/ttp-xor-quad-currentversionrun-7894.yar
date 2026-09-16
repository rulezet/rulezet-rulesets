rule TTP_XOR_QUAD_CurrentVersionRun_7894 {
  strings:
    $key_7894 = { 2b fb [2] 0f f5 [2] 24 d9 [2] 0a fb [2] 1e e0 [2] 11 fa [2] 0f e7 [2] 0d e6 [2] 16 e0 [2] 0a e7 [2] 16 c8 }

  condition:
    any of them
}