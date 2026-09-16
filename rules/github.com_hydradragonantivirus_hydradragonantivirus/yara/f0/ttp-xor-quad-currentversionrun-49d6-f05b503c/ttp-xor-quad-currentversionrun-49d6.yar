rule TTP_XOR_QUAD_CurrentVersionRun_49d6 {
  strings:
    $key_49d6 = { 1a b9 [2] 3e b7 [2] 15 9b [2] 3b b9 [2] 2f a2 [2] 20 b8 [2] 3e a5 [2] 3c a4 [2] 27 a2 [2] 3b a5 [2] 27 8a }

  condition:
    any of them
}