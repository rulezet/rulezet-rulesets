rule TTP_XOR_QUAD_CurrentVersionRun_0bd6 {
  strings:
    $key_0bd6 = { 58 b9 [2] 7c b7 [2] 57 9b [2] 79 b9 [2] 6d a2 [2] 62 b8 [2] 7c a5 [2] 7e a4 [2] 65 a2 [2] 79 a5 [2] 65 8a }

  condition:
    any of them
}