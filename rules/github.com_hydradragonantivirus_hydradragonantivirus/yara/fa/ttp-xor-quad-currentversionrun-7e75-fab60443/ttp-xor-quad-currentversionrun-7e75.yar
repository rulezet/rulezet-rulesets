rule TTP_XOR_QUAD_CurrentVersionRun_7e75 {
  strings:
    $key_7e75 = { 2d 1a [2] 09 14 [2] 22 38 [2] 0c 1a [2] 18 01 [2] 17 1b [2] 09 06 [2] 0b 07 [2] 10 01 [2] 0c 06 [2] 10 29 }

  condition:
    any of them
}