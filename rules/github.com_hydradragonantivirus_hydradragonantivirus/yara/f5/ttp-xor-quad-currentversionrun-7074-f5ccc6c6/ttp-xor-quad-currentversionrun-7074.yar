rule TTP_XOR_QUAD_CurrentVersionRun_7074 {
  strings:
    $key_7074 = { 23 1b [2] 07 15 [2] 2c 39 [2] 02 1b [2] 16 00 [2] 19 1a [2] 07 07 [2] 05 06 [2] 1e 00 [2] 02 07 [2] 1e 28 }

  condition:
    any of them
}