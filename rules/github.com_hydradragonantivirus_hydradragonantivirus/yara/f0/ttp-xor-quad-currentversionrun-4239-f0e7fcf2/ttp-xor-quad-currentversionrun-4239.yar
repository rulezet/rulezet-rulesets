rule TTP_XOR_QUAD_CurrentVersionRun_4239 {
  strings:
    $key_4239 = { 11 56 [2] 35 58 [2] 1e 74 [2] 30 56 [2] 24 4d [2] 2b 57 [2] 35 4a [2] 37 4b [2] 2c 4d [2] 30 4a [2] 2c 65 }

  condition:
    any of them
}