rule TTP_XOR_QUAD_CurrentVersionRun_f39b {
  strings:
    $key_f39b = { a0 f4 [2] 84 fa [2] af d6 [2] 81 f4 [2] 95 ef [2] 9a f5 [2] 84 e8 [2] 86 e9 [2] 9d ef [2] 81 e8 [2] 9d c7 }

  condition:
    any of them
}