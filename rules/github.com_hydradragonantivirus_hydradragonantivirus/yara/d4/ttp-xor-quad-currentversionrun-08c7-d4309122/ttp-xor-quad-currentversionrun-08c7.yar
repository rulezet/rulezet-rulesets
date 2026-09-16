rule TTP_XOR_QUAD_CurrentVersionRun_08c7 {
  strings:
    $key_08c7 = { 5b a8 [2] 7f a6 [2] 54 8a [2] 7a a8 [2] 6e b3 [2] 61 a9 [2] 7f b4 [2] 7d b5 [2] 66 b3 [2] 7a b4 [2] 66 9b }

  condition:
    any of them
}