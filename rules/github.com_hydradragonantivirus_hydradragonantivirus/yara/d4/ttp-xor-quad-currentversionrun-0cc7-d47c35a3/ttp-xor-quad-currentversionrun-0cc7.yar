rule TTP_XOR_QUAD_CurrentVersionRun_0cc7 {
  strings:
    $key_0cc7 = { 5f a8 [2] 7b a6 [2] 50 8a [2] 7e a8 [2] 6a b3 [2] 65 a9 [2] 7b b4 [2] 79 b5 [2] 62 b3 [2] 7e b4 [2] 62 9b }

  condition:
    any of them
}