rule TTP_XOR_QUAD_CurrentVersionRun_2cd6 {
  strings:
    $key_2cd6 = { 7f b9 [2] 5b b7 [2] 70 9b [2] 5e b9 [2] 4a a2 [2] 45 b8 [2] 5b a5 [2] 59 a4 [2] 42 a2 [2] 5e a5 [2] 42 8a }

  condition:
    any of them
}