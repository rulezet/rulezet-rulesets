rule TTP_XOR_QUAD_CurrentVersionRun_f097 {
  strings:
    $key_f097 = { a3 f8 [2] 87 f6 [2] ac da [2] 82 f8 [2] 96 e3 [2] 99 f9 [2] 87 e4 [2] 85 e5 [2] 9e e3 [2] 82 e4 [2] 9e cb }

  condition:
    any of them
}