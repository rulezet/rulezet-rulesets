rule TTP_XOR_QUAD_CurrentVersionRun_7079 {
  strings:
    $key_7079 = { 23 16 [2] 07 18 [2] 2c 34 [2] 02 16 [2] 16 0d [2] 19 17 [2] 07 0a [2] 05 0b [2] 1e 0d [2] 02 0a [2] 1e 25 }

  condition:
    any of them
}