rule TTP_XOR_QUAD_CurrentVersionRun_7b75 {
  strings:
    $key_7b75 = { 28 1a [2] 0c 14 [2] 27 38 [2] 09 1a [2] 1d 01 [2] 12 1b [2] 0c 06 [2] 0e 07 [2] 15 01 [2] 09 06 [2] 15 29 }

  condition:
    any of them
}