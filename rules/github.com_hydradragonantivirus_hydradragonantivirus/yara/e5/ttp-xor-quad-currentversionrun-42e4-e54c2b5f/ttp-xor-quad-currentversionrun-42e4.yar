rule TTP_XOR_QUAD_CurrentVersionRun_42e4 {
  strings:
    $key_42e4 = { 11 8b [2] 35 85 [2] 1e a9 [2] 30 8b [2] 24 90 [2] 2b 8a [2] 35 97 [2] 37 96 [2] 2c 90 [2] 30 97 [2] 2c b8 }

  condition:
    any of them
}