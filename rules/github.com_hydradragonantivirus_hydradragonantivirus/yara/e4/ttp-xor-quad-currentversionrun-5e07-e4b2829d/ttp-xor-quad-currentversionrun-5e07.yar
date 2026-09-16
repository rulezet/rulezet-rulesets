rule TTP_XOR_QUAD_CurrentVersionRun_5e07 {
  strings:
    $key_5e07 = { 0d 68 [2] 29 66 [2] 02 4a [2] 2c 68 [2] 38 73 [2] 37 69 [2] 29 74 [2] 2b 75 [2] 30 73 [2] 2c 74 [2] 30 5b }

  condition:
    any of them
}