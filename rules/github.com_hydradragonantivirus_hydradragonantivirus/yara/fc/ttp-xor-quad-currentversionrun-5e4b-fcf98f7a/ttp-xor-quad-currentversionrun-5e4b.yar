rule TTP_XOR_QUAD_CurrentVersionRun_5e4b {
  strings:
    $key_5e4b = { 0d 24 [2] 29 2a [2] 02 06 [2] 2c 24 [2] 38 3f [2] 37 25 [2] 29 38 [2] 2b 39 [2] 30 3f [2] 2c 38 [2] 30 17 }

  condition:
    any of them
}