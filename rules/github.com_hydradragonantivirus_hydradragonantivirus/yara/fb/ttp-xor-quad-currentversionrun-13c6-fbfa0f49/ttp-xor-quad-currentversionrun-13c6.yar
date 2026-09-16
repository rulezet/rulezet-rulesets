rule TTP_XOR_QUAD_CurrentVersionRun_13c6 {
  strings:
    $key_13c6 = { 40 a9 [2] 64 a7 [2] 4f 8b [2] 61 a9 [2] 75 b2 [2] 7a a8 [2] 64 b5 [2] 66 b4 [2] 7d b2 [2] 61 b5 [2] 7d 9a }

  condition:
    any of them
}