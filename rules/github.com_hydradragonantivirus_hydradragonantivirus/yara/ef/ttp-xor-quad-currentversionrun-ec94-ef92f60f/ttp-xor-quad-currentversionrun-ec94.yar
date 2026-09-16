rule TTP_XOR_QUAD_CurrentVersionRun_ec94 {
  strings:
    $key_ec94 = { bf fb [2] 9b f5 [2] b0 d9 [2] 9e fb [2] 8a e0 [2] 85 fa [2] 9b e7 [2] 99 e6 [2] 82 e0 [2] 9e e7 [2] 82 c8 }

  condition:
    any of them
}