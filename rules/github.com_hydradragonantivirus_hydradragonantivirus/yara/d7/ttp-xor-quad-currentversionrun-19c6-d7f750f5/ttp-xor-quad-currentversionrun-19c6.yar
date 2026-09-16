rule TTP_XOR_QUAD_CurrentVersionRun_19c6 {
  strings:
    $key_19c6 = { 4a a9 [2] 6e a7 [2] 45 8b [2] 6b a9 [2] 7f b2 [2] 70 a8 [2] 6e b5 [2] 6c b4 [2] 77 b2 [2] 6b b5 [2] 77 9a }

  condition:
    any of them
}