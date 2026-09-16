rule TTP_XOR_QUAD_CurrentVersionRun_31c7 {
  strings:
    $key_31c7 = { 62 a8 [2] 46 a6 [2] 6d 8a [2] 43 a8 [2] 57 b3 [2] 58 a9 [2] 46 b4 [2] 44 b5 [2] 5f b3 [2] 43 b4 [2] 5f 9b }

  condition:
    any of them
}