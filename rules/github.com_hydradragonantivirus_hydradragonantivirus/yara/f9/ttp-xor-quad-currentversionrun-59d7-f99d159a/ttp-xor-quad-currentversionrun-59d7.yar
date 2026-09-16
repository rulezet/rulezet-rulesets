rule TTP_XOR_QUAD_CurrentVersionRun_59d7 {
  strings:
    $key_59d7 = { 0a b8 [2] 2e b6 [2] 05 9a [2] 2b b8 [2] 3f a3 [2] 30 b9 [2] 2e a4 [2] 2c a5 [2] 37 a3 [2] 2b a4 [2] 37 8b }

  condition:
    any of them
}