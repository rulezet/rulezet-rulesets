rule TTP_XOR_QUAD_CurrentVersionRun_456e {
  strings:
    $key_456e = { 16 01 [2] 32 0f [2] 19 23 [2] 37 01 [2] 23 1a [2] 2c 00 [2] 32 1d [2] 30 1c [2] 2b 1a [2] 37 1d [2] 2b 32 }

  condition:
    any of them
}