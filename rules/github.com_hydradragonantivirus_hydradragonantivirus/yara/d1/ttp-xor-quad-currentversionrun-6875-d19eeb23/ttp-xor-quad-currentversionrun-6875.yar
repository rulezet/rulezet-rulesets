rule TTP_XOR_QUAD_CurrentVersionRun_6875 {
  strings:
    $key_6875 = { 3b 1a [2] 1f 14 [2] 34 38 [2] 1a 1a [2] 0e 01 [2] 01 1b [2] 1f 06 [2] 1d 07 [2] 06 01 [2] 1a 06 [2] 06 29 }

  condition:
    any of them
}