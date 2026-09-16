rule TTP_XOR_QUAD_CurrentVersionRun_71c6 {
  strings:
    $key_71c6 = { 22 a9 [2] 06 a7 [2] 2d 8b [2] 03 a9 [2] 17 b2 [2] 18 a8 [2] 06 b5 [2] 04 b4 [2] 1f b2 [2] 03 b5 [2] 1f 9a }

  condition:
    any of them
}