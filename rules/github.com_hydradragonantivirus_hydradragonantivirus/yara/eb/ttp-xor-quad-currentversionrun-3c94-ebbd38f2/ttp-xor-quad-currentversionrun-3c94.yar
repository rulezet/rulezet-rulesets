rule TTP_XOR_QUAD_CurrentVersionRun_3c94 {
  strings:
    $key_3c94 = { 6f fb [2] 4b f5 [2] 60 d9 [2] 4e fb [2] 5a e0 [2] 55 fa [2] 4b e7 [2] 49 e6 [2] 52 e0 [2] 4e e7 [2] 52 c8 }

  condition:
    any of them
}