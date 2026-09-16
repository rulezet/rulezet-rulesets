rule TTP_XOR_QUAD_CurrentVersionRun_19d7 {
  strings:
    $key_19d7 = { 4a b8 [2] 6e b6 [2] 45 9a [2] 6b b8 [2] 7f a3 [2] 70 b9 [2] 6e a4 [2] 6c a5 [2] 77 a3 [2] 6b a4 [2] 77 8b }

  condition:
    any of them
}