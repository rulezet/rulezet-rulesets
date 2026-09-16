rule TTP_XOR_QUAD_CurrentVersionRun_45d5 {
  strings:
    $key_45d5 = { 16 ba [2] 32 b4 [2] 19 98 [2] 37 ba [2] 23 a1 [2] 2c bb [2] 32 a6 [2] 30 a7 [2] 2b a1 [2] 37 a6 [2] 2b 89 }

  condition:
    any of them
}