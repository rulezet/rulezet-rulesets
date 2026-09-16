rule TTP_XOR_QUAD_CurrentVersionRun_4475 {
  strings:
    $key_4475 = { 17 1a [2] 33 14 [2] 18 38 [2] 36 1a [2] 22 01 [2] 2d 1b [2] 33 06 [2] 31 07 [2] 2a 01 [2] 36 06 [2] 2a 29 }

  condition:
    any of them
}