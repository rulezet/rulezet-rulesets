rule TTP_XOR_QUAD_CurrentVersionRun_4fc7 {
  strings:
    $key_4fc7 = { 1c a8 [2] 38 a6 [2] 13 8a [2] 3d a8 [2] 29 b3 [2] 26 a9 [2] 38 b4 [2] 3a b5 [2] 21 b3 [2] 3d b4 [2] 21 9b }

  condition:
    any of them
}