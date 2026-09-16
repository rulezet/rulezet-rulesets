rule TTP_XOR_QUAD_CurrentVersionRun_23c7 {
  strings:
    $key_23c7 = { 70 a8 [2] 54 a6 [2] 7f 8a [2] 51 a8 [2] 45 b3 [2] 4a a9 [2] 54 b4 [2] 56 b5 [2] 4d b3 [2] 51 b4 [2] 4d 9b }

  condition:
    any of them
}