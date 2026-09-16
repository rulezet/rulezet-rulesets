rule TTP_XOR_QUAD_CurrentVersionRun_0bd7 {
  strings:
    $key_0bd7 = { 58 b8 [2] 7c b6 [2] 57 9a [2] 79 b8 [2] 6d a3 [2] 62 b9 [2] 7c a4 [2] 7e a5 [2] 65 a3 [2] 79 a4 [2] 65 8b }

  condition:
    any of them
}