rule TTP_XOR_QUAD_CurrentVersionRun_5e79 {
  strings:
    $key_5e79 = { 0d 16 [2] 29 18 [2] 02 34 [2] 2c 16 [2] 38 0d [2] 37 17 [2] 29 0a [2] 2b 0b [2] 30 0d [2] 2c 0a [2] 30 25 }

  condition:
    any of them
}