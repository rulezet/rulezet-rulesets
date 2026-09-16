rule TTP_XOR_QUAD_CurrentVersionRun_31d5 {
  strings:
    $key_31d5 = { 62 ba [2] 46 b4 [2] 6d 98 [2] 43 ba [2] 57 a1 [2] 58 bb [2] 46 a6 [2] 44 a7 [2] 5f a1 [2] 43 a6 [2] 5f 89 }

  condition:
    any of them
}