rule TTP_XOR_QUAD_CurrentVersionRun_06c7 {
  strings:
    $key_06c7 = { 55 a8 [2] 71 a6 [2] 5a 8a [2] 74 a8 [2] 60 b3 [2] 6f a9 [2] 71 b4 [2] 73 b5 [2] 68 b3 [2] 74 b4 [2] 68 9b }

  condition:
    any of them
}