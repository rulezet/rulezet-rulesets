rule TTP_XOR_QUAD_CurrentVersionRun_71d4 {
  strings:
    $key_71d4 = { 22 bb [2] 06 b5 [2] 2d 99 [2] 03 bb [2] 17 a0 [2] 18 ba [2] 06 a7 [2] 04 a6 [2] 1f a0 [2] 03 a7 [2] 1f 88 }

  condition:
    any of them
}