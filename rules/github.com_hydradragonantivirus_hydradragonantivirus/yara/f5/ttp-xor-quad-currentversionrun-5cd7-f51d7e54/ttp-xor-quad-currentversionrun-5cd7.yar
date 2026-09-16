rule TTP_XOR_QUAD_CurrentVersionRun_5cd7 {
  strings:
    $key_5cd7 = { 0f b8 [2] 2b b6 [2] 00 9a [2] 2e b8 [2] 3a a3 [2] 35 b9 [2] 2b a4 [2] 29 a5 [2] 32 a3 [2] 2e a4 [2] 32 8b }

  condition:
    any of them
}