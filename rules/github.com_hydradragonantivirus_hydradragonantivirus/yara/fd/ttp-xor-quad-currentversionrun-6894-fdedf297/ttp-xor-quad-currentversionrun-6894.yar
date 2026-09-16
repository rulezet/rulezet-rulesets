rule TTP_XOR_QUAD_CurrentVersionRun_6894 {
  strings:
    $key_6894 = { 3b fb [2] 1f f5 [2] 34 d9 [2] 1a fb [2] 0e e0 [2] 01 fa [2] 1f e7 [2] 1d e6 [2] 06 e0 [2] 1a e7 [2] 06 c8 }

  condition:
    any of them
}