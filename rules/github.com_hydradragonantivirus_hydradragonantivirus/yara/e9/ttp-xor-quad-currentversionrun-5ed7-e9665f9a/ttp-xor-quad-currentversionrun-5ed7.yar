rule TTP_XOR_QUAD_CurrentVersionRun_5ed7 {
  strings:
    $key_5ed7 = { 0d b8 [2] 29 b6 [2] 02 9a [2] 2c b8 [2] 38 a3 [2] 37 b9 [2] 29 a4 [2] 2b a5 [2] 30 a3 [2] 2c a4 [2] 30 8b }

  condition:
    any of them
}