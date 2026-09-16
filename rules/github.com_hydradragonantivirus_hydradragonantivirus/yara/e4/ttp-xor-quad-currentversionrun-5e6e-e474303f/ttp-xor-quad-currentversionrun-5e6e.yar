rule TTP_XOR_QUAD_CurrentVersionRun_5e6e {
  strings:
    $key_5e6e = { 0d 01 [2] 29 0f [2] 02 23 [2] 2c 01 [2] 38 1a [2] 37 00 [2] 29 1d [2] 2b 1c [2] 30 1a [2] 2c 1d [2] 30 32 }

  condition:
    any of them
}