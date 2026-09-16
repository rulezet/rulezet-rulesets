rule TTP_XOR_QUAD_CurrentVersionRun_6f75 {
  strings:
    $key_6f75 = { 3c 1a [2] 18 14 [2] 33 38 [2] 1d 1a [2] 09 01 [2] 06 1b [2] 18 06 [2] 1a 07 [2] 01 01 [2] 1d 06 [2] 01 29 }

  condition:
    any of them
}