rule TTP_XOR_QUAD_CurrentVersionRun_36c7 {
  strings:
    $key_36c7 = { 65 a8 [2] 41 a6 [2] 6a 8a [2] 44 a8 [2] 50 b3 [2] 5f a9 [2] 41 b4 [2] 43 b5 [2] 58 b3 [2] 44 b4 [2] 58 9b }

  condition:
    any of them
}