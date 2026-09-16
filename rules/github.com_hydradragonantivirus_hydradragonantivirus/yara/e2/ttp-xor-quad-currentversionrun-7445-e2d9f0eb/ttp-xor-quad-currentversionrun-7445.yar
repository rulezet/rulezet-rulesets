rule TTP_XOR_QUAD_CurrentVersionRun_7445 {
  strings:
    $key_7445 = { 27 2a [2] 03 24 [2] 28 08 [2] 06 2a [2] 12 31 [2] 1d 2b [2] 03 36 [2] 01 37 [2] 1a 31 [2] 06 36 [2] 1a 19 }

  condition:
    any of them
}