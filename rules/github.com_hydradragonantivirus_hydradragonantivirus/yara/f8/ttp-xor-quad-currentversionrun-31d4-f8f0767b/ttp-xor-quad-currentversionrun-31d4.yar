rule TTP_XOR_QUAD_CurrentVersionRun_31d4 {
  strings:
    $key_31d4 = { 62 bb [2] 46 b5 [2] 6d 99 [2] 43 bb [2] 57 a0 [2] 58 ba [2] 46 a7 [2] 44 a6 [2] 5f a0 [2] 43 a7 [2] 5f 88 }

  condition:
    any of them
}