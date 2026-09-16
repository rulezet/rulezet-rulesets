rule TTP_XOR_QUAD_CurrentVersionRun_4e75 {
  strings:
    $key_4e75 = { 1d 1a [2] 39 14 [2] 12 38 [2] 3c 1a [2] 28 01 [2] 27 1b [2] 39 06 [2] 3b 07 [2] 20 01 [2] 3c 06 [2] 20 29 }

  condition:
    any of them
}