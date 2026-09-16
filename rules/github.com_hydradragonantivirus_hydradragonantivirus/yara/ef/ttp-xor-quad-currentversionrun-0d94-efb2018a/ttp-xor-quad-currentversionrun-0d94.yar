rule TTP_XOR_QUAD_CurrentVersionRun_0d94 {
  strings:
    $key_0d94 = { 5e fb [2] 7a f5 [2] 51 d9 [2] 7f fb [2] 6b e0 [2] 64 fa [2] 7a e7 [2] 78 e6 [2] 63 e0 [2] 7f e7 [2] 63 c8 }

  condition:
    any of them
}