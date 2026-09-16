rule TTP_XOR_QUAD_CurrentVersionRun_1d74 {
  strings:
    $key_1d74 = { 4e 1b [2] 6a 15 [2] 41 39 [2] 6f 1b [2] 7b 00 [2] 74 1a [2] 6a 07 [2] 68 06 [2] 73 00 [2] 6f 07 [2] 73 28 }

  condition:
    any of them
}