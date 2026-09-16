rule TTP_XOR_QUAD_CurrentVersionRun_33c7 {
  strings:
    $key_33c7 = { 60 a8 [2] 44 a6 [2] 6f 8a [2] 41 a8 [2] 55 b3 [2] 5a a9 [2] 44 b4 [2] 46 b5 [2] 5d b3 [2] 41 b4 [2] 5d 9b }

  condition:
    any of them
}