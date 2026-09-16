rule TTP_XOR_QUAD_CurrentVersionRun_2cc6 {
  strings:
    $key_2cc6 = { 7f a9 [2] 5b a7 [2] 70 8b [2] 5e a9 [2] 4a b2 [2] 45 a8 [2] 5b b5 [2] 59 b4 [2] 42 b2 [2] 5e b5 [2] 42 9a }

  condition:
    any of them
}