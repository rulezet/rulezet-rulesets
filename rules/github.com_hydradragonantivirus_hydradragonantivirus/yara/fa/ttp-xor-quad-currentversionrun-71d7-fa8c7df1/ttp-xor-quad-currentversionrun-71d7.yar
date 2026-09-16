rule TTP_XOR_QUAD_CurrentVersionRun_71d7 {
  strings:
    $key_71d7 = { 22 b8 [2] 06 b6 [2] 2d 9a [2] 03 b8 [2] 17 a3 [2] 18 b9 [2] 06 a4 [2] 04 a5 [2] 1f a3 [2] 03 a4 [2] 1f 8b }

  condition:
    any of them
}