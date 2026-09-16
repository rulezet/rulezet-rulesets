rule TTP_XOR_QUAD_CurrentVersionRun_08c6 {
  strings:
    $key_08c6 = { 5b a9 [2] 7f a7 [2] 54 8b [2] 7a a9 [2] 6e b2 [2] 61 a8 [2] 7f b5 [2] 7d b4 [2] 66 b2 [2] 7a b5 [2] 66 9a }

  condition:
    any of them
}