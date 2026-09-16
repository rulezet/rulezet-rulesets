rule TTP_XOR_QUAD_CurrentVersionRun_3cd6 {
  strings:
    $key_3cd6 = { 6f b9 [2] 4b b7 [2] 60 9b [2] 4e b9 [2] 5a a2 [2] 55 b8 [2] 4b a5 [2] 49 a4 [2] 52 a2 [2] 4e a5 [2] 52 8a }

  condition:
    any of them
}