rule TTP_XOR_QUAD_CurrentVersionRun_5e17 {
  strings:
    $key_5e17 = { 0d 78 [2] 29 76 [2] 02 5a [2] 2c 78 [2] 38 63 [2] 37 79 [2] 29 64 [2] 2b 65 [2] 30 63 [2] 2c 64 [2] 30 4b }

  condition:
    any of them
}