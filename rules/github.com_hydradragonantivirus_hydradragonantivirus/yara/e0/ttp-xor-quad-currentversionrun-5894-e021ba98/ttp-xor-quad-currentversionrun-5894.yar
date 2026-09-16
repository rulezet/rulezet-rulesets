rule TTP_XOR_QUAD_CurrentVersionRun_5894 {
  strings:
    $key_5894 = { 0b fb [2] 2f f5 [2] 04 d9 [2] 2a fb [2] 3e e0 [2] 31 fa [2] 2f e7 [2] 2d e6 [2] 36 e0 [2] 2a e7 [2] 36 c8 }

  condition:
    any of them
}