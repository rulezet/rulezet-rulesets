rule TTP_XOR_QUAD_CurrentVersionRun_0dc6 {
  strings:
    $key_0dc6 = { 5e a9 [2] 7a a7 [2] 51 8b [2] 7f a9 [2] 6b b2 [2] 64 a8 [2] 7a b5 [2] 78 b4 [2] 63 b2 [2] 7f b5 [2] 63 9a }

  condition:
    any of them
}