rule TTP_XOR_QUAD_CurrentVersionRun_f3b5 {
  strings:
    $key_f3b5 = { a0 da [2] 84 d4 [2] af f8 [2] 81 da [2] 95 c1 [2] 9a db [2] 84 c6 [2] 86 c7 [2] 9d c1 [2] 81 c6 [2] 9d e9 }

  condition:
    any of them
}