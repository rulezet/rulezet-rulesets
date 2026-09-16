rule TTP_XOR_QUAD_CurrentVersionRun_09c6 {
  strings:
    $key_09c6 = { 5a a9 [2] 7e a7 [2] 55 8b [2] 7b a9 [2] 6f b2 [2] 60 a8 [2] 7e b5 [2] 7c b4 [2] 67 b2 [2] 7b b5 [2] 67 9a }

  condition:
    any of them
}