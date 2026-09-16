rule TTP_XOR_QUAD_CurrentVersionRun_5ed6 {
  strings:
    $key_5ed6 = { 0d b9 [2] 29 b7 [2] 02 9b [2] 2c b9 [2] 38 a2 [2] 37 b8 [2] 29 a5 [2] 2b a4 [2] 30 a2 [2] 2c a5 [2] 30 8a }

  condition:
    any of them
}