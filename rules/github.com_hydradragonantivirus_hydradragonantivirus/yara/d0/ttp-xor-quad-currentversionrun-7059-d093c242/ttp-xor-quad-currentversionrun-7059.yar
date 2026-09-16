rule TTP_XOR_QUAD_CurrentVersionRun_7059 {
  strings:
    $key_7059 = { 23 36 [2] 07 38 [2] 2c 14 [2] 02 36 [2] 16 2d [2] 19 37 [2] 07 2a [2] 05 2b [2] 1e 2d [2] 02 2a [2] 1e 05 }

  condition:
    any of them
}