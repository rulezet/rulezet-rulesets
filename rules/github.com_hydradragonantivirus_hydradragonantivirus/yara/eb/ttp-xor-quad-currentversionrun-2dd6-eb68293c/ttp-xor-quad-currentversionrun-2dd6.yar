rule TTP_XOR_QUAD_CurrentVersionRun_2dd6 {
  strings:
    $key_2dd6 = { 7e b9 [2] 5a b7 [2] 71 9b [2] 5f b9 [2] 4b a2 [2] 44 b8 [2] 5a a5 [2] 58 a4 [2] 43 a2 [2] 5f a5 [2] 43 8a }

  condition:
    any of them
}