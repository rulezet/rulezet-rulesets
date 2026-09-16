rule TTP_XOR_QUAD_CurrentVersionRun_f394 {
  strings:
    $key_f394 = { a0 fb [2] 84 f5 [2] af d9 [2] 81 fb [2] 95 e0 [2] 9a fa [2] 84 e7 [2] 86 e6 [2] 9d e0 [2] 81 e7 [2] 9d c8 }

  condition:
    any of them
}