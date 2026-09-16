rule TTP_XOR_QUAD_CurrentVersionRun_7f75 {
  strings:
    $key_7f75 = { 2c 1a [2] 08 14 [2] 23 38 [2] 0d 1a [2] 19 01 [2] 16 1b [2] 08 06 [2] 0a 07 [2] 11 01 [2] 0d 06 [2] 11 29 }

  condition:
    any of them
}