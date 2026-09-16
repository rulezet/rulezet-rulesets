rule TTP_XOR_QUAD_CurrentVersionRun_5e0b {
  strings:
    $key_5e0b = { 0d 64 [2] 29 6a [2] 02 46 [2] 2c 64 [2] 38 7f [2] 37 65 [2] 29 78 [2] 2b 79 [2] 30 7f [2] 2c 78 [2] 30 57 }

  condition:
    any of them
}