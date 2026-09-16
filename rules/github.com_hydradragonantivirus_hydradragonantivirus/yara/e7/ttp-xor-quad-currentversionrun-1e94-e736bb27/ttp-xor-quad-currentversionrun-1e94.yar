rule TTP_XOR_QUAD_CurrentVersionRun_1e94 {
  strings:
    $key_1e94 = { 4d fb [2] 69 f5 [2] 42 d9 [2] 6c fb [2] 78 e0 [2] 77 fa [2] 69 e7 [2] 6b e6 [2] 70 e0 [2] 6c e7 [2] 70 c8 }

  condition:
    any of them
}