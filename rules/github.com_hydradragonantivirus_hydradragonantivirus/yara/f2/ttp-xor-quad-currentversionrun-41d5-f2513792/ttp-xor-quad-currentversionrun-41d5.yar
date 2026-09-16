rule TTP_XOR_QUAD_CurrentVersionRun_41d5 {
  strings:
    $key_41d5 = { 12 ba [2] 36 b4 [2] 1d 98 [2] 33 ba [2] 27 a1 [2] 28 bb [2] 36 a6 [2] 34 a7 [2] 2f a1 [2] 33 a6 [2] 2f 89 }

  condition:
    any of them
}