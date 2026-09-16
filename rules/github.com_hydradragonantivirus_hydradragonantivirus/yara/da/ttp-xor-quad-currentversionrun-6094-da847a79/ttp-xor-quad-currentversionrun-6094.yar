rule TTP_XOR_QUAD_CurrentVersionRun_6094 {
  strings:
    $key_6094 = { 33 fb [2] 17 f5 [2] 3c d9 [2] 12 fb [2] 06 e0 [2] 09 fa [2] 17 e7 [2] 15 e6 [2] 0e e0 [2] 12 e7 [2] 0e c8 }

  condition:
    any of them
}