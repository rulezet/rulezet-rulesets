rule TTP_XOR_QUAD_CurrentVersionRun_25d7 {
  strings:
    $key_25d7 = { 76 b8 [2] 52 b6 [2] 79 9a [2] 57 b8 [2] 43 a3 [2] 4c b9 [2] 52 a4 [2] 50 a5 [2] 4b a3 [2] 57 a4 [2] 4b 8b }

  condition:
    any of them
}