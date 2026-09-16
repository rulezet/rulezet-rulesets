rule TTP_XOR_QUAD_CurrentVersionRun_5e3b {
  strings:
    $key_5e3b = { 0d 54 [2] 29 5a [2] 02 76 [2] 2c 54 [2] 38 4f [2] 37 55 [2] 29 48 [2] 2b 49 [2] 30 4f [2] 2c 48 [2] 30 67 }

  condition:
    any of them
}