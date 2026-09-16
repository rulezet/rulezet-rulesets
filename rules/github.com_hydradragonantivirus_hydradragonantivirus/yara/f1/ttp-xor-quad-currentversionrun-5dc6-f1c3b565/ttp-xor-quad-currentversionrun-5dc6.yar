rule TTP_XOR_QUAD_CurrentVersionRun_5dc6 {
  strings:
    $key_5dc6 = { 0e a9 [2] 2a a7 [2] 01 8b [2] 2f a9 [2] 3b b2 [2] 34 a8 [2] 2a b5 [2] 28 b4 [2] 33 b2 [2] 2f b5 [2] 33 9a }

  condition:
    any of them
}