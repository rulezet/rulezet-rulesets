rule TTP_XOR_QUAD_CurrentVersionRun_2c94 {
  strings:
    $key_2c94 = { 7f fb [2] 5b f5 [2] 70 d9 [2] 5e fb [2] 4a e0 [2] 45 fa [2] 5b e7 [2] 59 e6 [2] 42 e0 [2] 5e e7 [2] 42 c8 }

  condition:
    any of them
}