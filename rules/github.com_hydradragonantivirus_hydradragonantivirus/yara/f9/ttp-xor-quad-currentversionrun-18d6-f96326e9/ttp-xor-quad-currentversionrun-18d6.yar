rule TTP_XOR_QUAD_CurrentVersionRun_18d6 {
  strings:
    $key_18d6 = { 4b b9 [2] 6f b7 [2] 44 9b [2] 6a b9 [2] 7e a2 [2] 71 b8 [2] 6f a5 [2] 6d a4 [2] 76 a2 [2] 6a a5 [2] 76 8a }

  condition:
    any of them
}