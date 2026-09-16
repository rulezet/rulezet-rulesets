rule TTP_XOR_QUAD_CurrentVersionRun_45d7 {
  strings:
    $key_45d7 = { 16 b8 [2] 32 b6 [2] 19 9a [2] 37 b8 [2] 23 a3 [2] 2c b9 [2] 32 a4 [2] 30 a5 [2] 2b a3 [2] 37 a4 [2] 2b 8b }

  condition:
    any of them
}