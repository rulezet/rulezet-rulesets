rule TTP_XOR_QUAD_CurrentVersionRun_3dd6 {
  strings:
    $key_3dd6 = { 6e b9 [2] 4a b7 [2] 61 9b [2] 4f b9 [2] 5b a2 [2] 54 b8 [2] 4a a5 [2] 48 a4 [2] 53 a2 [2] 4f a5 [2] 53 8a }

  condition:
    any of them
}