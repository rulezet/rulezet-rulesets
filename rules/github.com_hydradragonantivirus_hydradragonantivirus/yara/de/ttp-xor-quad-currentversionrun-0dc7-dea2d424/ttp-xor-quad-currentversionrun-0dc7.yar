rule TTP_XOR_QUAD_CurrentVersionRun_0dc7 {
  strings:
    $key_0dc7 = { 5e a8 [2] 7a a6 [2] 51 8a [2] 7f a8 [2] 6b b3 [2] 64 a9 [2] 7a b4 [2] 78 b5 [2] 63 b3 [2] 7f b4 [2] 63 9b }

  condition:
    any of them
}