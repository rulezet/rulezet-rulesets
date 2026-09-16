rule TTP_XOR_QUAD_CurrentVersionRun_7374 {
  strings:
    $key_7374 = { 20 1b [2] 04 15 [2] 2f 39 [2] 01 1b [2] 15 00 [2] 1a 1a [2] 04 07 [2] 06 06 [2] 1d 00 [2] 01 07 [2] 1d 28 }

  condition:
    any of them
}