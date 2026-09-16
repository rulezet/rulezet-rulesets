rule TTP_XOR_QUAD_CurrentVersionRun_71d5 {
  strings:
    $key_71d5 = { 22 ba [2] 06 b4 [2] 2d 98 [2] 03 ba [2] 17 a1 [2] 18 bb [2] 06 a6 [2] 04 a7 [2] 1f a1 [2] 03 a6 [2] 1f 89 }

  condition:
    any of them
}