rule TTP_XOR_QUAD_CurrentVersionRun_2cc7 {
  strings:
    $key_2cc7 = { 7f a8 [2] 5b a6 [2] 70 8a [2] 5e a8 [2] 4a b3 [2] 45 a9 [2] 5b b4 [2] 59 b5 [2] 42 b3 [2] 5e b4 [2] 42 9b }

  condition:
    any of them
}