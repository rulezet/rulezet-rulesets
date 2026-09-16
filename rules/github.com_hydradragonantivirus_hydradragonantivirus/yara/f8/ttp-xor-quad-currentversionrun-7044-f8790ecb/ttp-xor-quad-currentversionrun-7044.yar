rule TTP_XOR_QUAD_CurrentVersionRun_7044 {
  strings:
    $key_7044 = { 23 2b [2] 07 25 [2] 2c 09 [2] 02 2b [2] 16 30 [2] 19 2a [2] 07 37 [2] 05 36 [2] 1e 30 [2] 02 37 [2] 1e 18 }

  condition:
    any of them
}