rule TTP_XOR_QUAD_CurrentVersionRun_1d75 {
  strings:
    $key_1d75 = { 4e 1a [2] 6a 14 [2] 41 38 [2] 6f 1a [2] 7b 01 [2] 74 1b [2] 6a 06 [2] 68 07 [2] 73 01 [2] 6f 06 [2] 73 29 }

  condition:
    any of them
}