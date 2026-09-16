rule TTP_XOR_QUAD_CurrentVersionRun_5e24 {
  strings:
    $key_5e24 = { 0d 4b [2] 29 45 [2] 02 69 [2] 2c 4b [2] 38 50 [2] 37 4a [2] 29 57 [2] 2b 56 [2] 30 50 [2] 2c 57 [2] 30 78 }

  condition:
    any of them
}