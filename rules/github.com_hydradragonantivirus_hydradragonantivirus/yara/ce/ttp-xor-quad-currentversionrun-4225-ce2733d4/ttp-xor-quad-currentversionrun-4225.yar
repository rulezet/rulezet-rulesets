rule TTP_XOR_QUAD_CurrentVersionRun_4225 {
  strings:
    $key_4225 = { 11 4a [2] 35 44 [2] 1e 68 [2] 30 4a [2] 24 51 [2] 2b 4b [2] 35 56 [2] 37 57 [2] 2c 51 [2] 30 56 [2] 2c 79 }

  condition:
    any of them
}