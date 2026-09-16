rule TTP_XOR_QUAD_CurrentVersionRun_1cd6 {
  strings:
    $key_1cd6 = { 4f b9 [2] 6b b7 [2] 40 9b [2] 6e b9 [2] 7a a2 [2] 75 b8 [2] 6b a5 [2] 69 a4 [2] 72 a2 [2] 6e a5 [2] 72 8a }

  condition:
    any of them
}