rule TTP_XOR_QUAD_CurrentVersionRun_39d6 {
  strings:
    $key_39d6 = { 6a b9 [2] 4e b7 [2] 65 9b [2] 4b b9 [2] 5f a2 [2] 50 b8 [2] 4e a5 [2] 4c a4 [2] 57 a2 [2] 4b a5 [2] 57 8a }

  condition:
    any of them
}