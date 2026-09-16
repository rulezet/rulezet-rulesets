rule TTP_XOR_QUAD_CurrentVersionRun_41c6 {
  strings:
    $key_41c6 = { 12 a9 [2] 36 a7 [2] 1d 8b [2] 33 a9 [2] 27 b2 [2] 28 a8 [2] 36 b5 [2] 34 b4 [2] 2f b2 [2] 33 b5 [2] 2f 9a }

  condition:
    any of them
}