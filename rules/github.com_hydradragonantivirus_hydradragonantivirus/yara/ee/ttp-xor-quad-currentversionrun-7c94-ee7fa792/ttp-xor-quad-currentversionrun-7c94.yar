rule TTP_XOR_QUAD_CurrentVersionRun_7c94 {
  strings:
    $key_7c94 = { 2f fb [2] 0b f5 [2] 20 d9 [2] 0e fb [2] 1a e0 [2] 15 fa [2] 0b e7 [2] 09 e6 [2] 12 e0 [2] 0e e7 [2] 12 c8 }

  condition:
    any of them
}