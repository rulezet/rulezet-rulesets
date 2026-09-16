rule TTP_XOR_QUAD_CurrentVersionRun_18c7 {
  strings:
    $key_18c7 = { 4b a8 [2] 6f a6 [2] 44 8a [2] 6a a8 [2] 7e b3 [2] 71 a9 [2] 6f b4 [2] 6d b5 [2] 76 b3 [2] 6a b4 [2] 76 9b }

  condition:
    any of them
}