rule TTP_XOR_QUAD_CurrentVersionRun_13c7 {
  strings:
    $key_13c7 = { 40 a8 [2] 64 a6 [2] 4f 8a [2] 61 a8 [2] 75 b3 [2] 7a a9 [2] 64 b4 [2] 66 b5 [2] 7d b3 [2] 61 b4 [2] 7d 9b }

  condition:
    any of them
}