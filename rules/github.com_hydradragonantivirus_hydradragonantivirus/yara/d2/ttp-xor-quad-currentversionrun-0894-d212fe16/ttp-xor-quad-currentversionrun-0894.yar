rule TTP_XOR_QUAD_CurrentVersionRun_0894 {
  strings:
    $key_0894 = { 5b fb [2] 7f f5 [2] 54 d9 [2] 7a fb [2] 6e e0 [2] 61 fa [2] 7f e7 [2] 7d e6 [2] 66 e0 [2] 7a e7 [2] 66 c8 }

  condition:
    any of them
}