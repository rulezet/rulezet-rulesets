rule TTP_XOR_QUAD_CurrentVersionRun_4507 {
  strings:
    $key_4507 = { 16 68 [2] 32 66 [2] 19 4a [2] 37 68 [2] 23 73 [2] 2c 69 [2] 32 74 [2] 30 75 [2] 2b 73 [2] 37 74 [2] 2b 5b }

  condition:
    any of them
}