rule TTP_XOR_QUAD_CurrentVersionRun_f1d5 {
  strings:
    $key_f1d5 = { a2 ba [2] 86 b4 [2] ad 98 [2] 83 ba [2] 97 a1 [2] 98 bb [2] 86 a6 [2] 84 a7 [2] 9f a1 [2] 83 a6 [2] 9f 89 }

  condition:
    any of them
}