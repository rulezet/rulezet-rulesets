rule TTP_XOR_QUAD_CurrentVersionRun_6375 {
  strings:
    $key_6375 = { 30 1a [2] 14 14 [2] 3f 38 [2] 11 1a [2] 05 01 [2] 0a 1b [2] 14 06 [2] 16 07 [2] 0d 01 [2] 11 06 [2] 0d 29 }

  condition:
    any of them
}