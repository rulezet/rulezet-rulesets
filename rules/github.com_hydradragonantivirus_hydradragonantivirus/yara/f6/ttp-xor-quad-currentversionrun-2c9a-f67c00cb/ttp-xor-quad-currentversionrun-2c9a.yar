rule TTP_XOR_QUAD_CurrentVersionRun_2c9a {
  strings:
    $key_2c9a = { 7f f5 [2] 5b fb [2] 70 d7 [2] 5e f5 [2] 4a ee [2] 45 f4 [2] 5b e9 [2] 59 e8 [2] 42 ee [2] 5e e9 [2] 42 c6 }

  condition:
    any of them
}