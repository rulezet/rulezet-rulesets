rule TTP_XOR_QUAD_CurrentVersionRun_5e7d {
  strings:
    $key_5e7d = { 0d 12 [2] 29 1c [2] 02 30 [2] 2c 12 [2] 38 09 [2] 37 13 [2] 29 0e [2] 2b 0f [2] 30 09 [2] 2c 0e [2] 30 21 }

  condition:
    any of them
}