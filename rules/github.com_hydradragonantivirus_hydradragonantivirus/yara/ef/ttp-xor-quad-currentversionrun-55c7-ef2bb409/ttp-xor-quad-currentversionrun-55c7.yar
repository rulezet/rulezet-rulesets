rule TTP_XOR_QUAD_CurrentVersionRun_55c7 {
  strings:
    $key_55c7 = { 06 a8 [2] 22 a6 [2] 09 8a [2] 27 a8 [2] 33 b3 [2] 3c a9 [2] 22 b4 [2] 20 b5 [2] 3b b3 [2] 27 b4 [2] 3b 9b }

  condition:
    any of them
}