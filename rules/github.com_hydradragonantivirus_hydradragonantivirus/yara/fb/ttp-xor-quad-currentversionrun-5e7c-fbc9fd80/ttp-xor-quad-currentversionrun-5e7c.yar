rule TTP_XOR_QUAD_CurrentVersionRun_5e7c {
  strings:
    $key_5e7c = { 0d 13 [2] 29 1d [2] 02 31 [2] 2c 13 [2] 38 08 [2] 37 12 [2] 29 0f [2] 2b 0e [2] 30 08 [2] 2c 0f [2] 30 20 }

  condition:
    any of them
}