rule TTP_XOR_QUAD_CurrentVersionRun_0b75 {
  strings:
    $key_0b75 = { 58 1a [2] 7c 14 [2] 57 38 [2] 79 1a [2] 6d 01 [2] 62 1b [2] 7c 06 [2] 7e 07 [2] 65 01 [2] 79 06 [2] 65 29 }

  condition:
    any of them
}