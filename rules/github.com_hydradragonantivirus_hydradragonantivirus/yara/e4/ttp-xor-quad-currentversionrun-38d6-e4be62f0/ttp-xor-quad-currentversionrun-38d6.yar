rule TTP_XOR_QUAD_CurrentVersionRun_38d6 {
  strings:
    $key_38d6 = { 6b b9 [2] 4f b7 [2] 64 9b [2] 4a b9 [2] 5e a2 [2] 51 b8 [2] 4f a5 [2] 4d a4 [2] 56 a2 [2] 4a a5 [2] 56 8a }

  condition:
    any of them
}