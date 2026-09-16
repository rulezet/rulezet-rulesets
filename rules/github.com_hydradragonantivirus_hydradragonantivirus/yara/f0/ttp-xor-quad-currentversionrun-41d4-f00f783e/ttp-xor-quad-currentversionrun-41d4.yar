rule TTP_XOR_QUAD_CurrentVersionRun_41d4 {
  strings:
    $key_41d4 = { 12 bb [2] 36 b5 [2] 1d 99 [2] 33 bb [2] 27 a0 [2] 28 ba [2] 36 a7 [2] 34 a6 [2] 2f a0 [2] 33 a7 [2] 2f 88 }

  condition:
    any of them
}