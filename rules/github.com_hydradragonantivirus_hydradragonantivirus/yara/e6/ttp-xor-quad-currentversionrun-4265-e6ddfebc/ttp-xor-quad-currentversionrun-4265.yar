rule TTP_XOR_QUAD_CurrentVersionRun_4265 {
  strings:
    $key_4265 = { 11 0a [2] 35 04 [2] 1e 28 [2] 30 0a [2] 24 11 [2] 2b 0b [2] 35 16 [2] 37 17 [2] 2c 11 [2] 30 16 [2] 2c 39 }

  condition:
    any of them
}