rule TTP_XOR_QUAD_CurrentVersionRun_5e6b {
  strings:
    $key_5e6b = { 0d 04 [2] 29 0a [2] 02 26 [2] 2c 04 [2] 38 1f [2] 37 05 [2] 29 18 [2] 2b 19 [2] 30 1f [2] 2c 18 [2] 30 37 }

  condition:
    any of them
}