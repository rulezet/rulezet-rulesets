rule TTP_XOR_QUAD_CurrentVersionRun_6dc6 {
  strings:
    $key_6dc6 = { 3e a9 [2] 1a a7 [2] 31 8b [2] 1f a9 [2] 0b b2 [2] 04 a8 [2] 1a b5 [2] 18 b4 [2] 03 b2 [2] 1f b5 [2] 03 9a }

  condition:
    any of them
}