rule TTP_XOR_QUAD_CurrentVersionRun_58c6 {
  strings:
    $key_58c6 = { 0b a9 [2] 2f a7 [2] 04 8b [2] 2a a9 [2] 3e b2 [2] 31 a8 [2] 2f b5 [2] 2d b4 [2] 36 b2 [2] 2a b5 [2] 36 9a }

  condition:
    any of them
}