rule TTP_XOR_QUAD_CurrentVersionRun_1d25 {
  strings:
    $key_1d25 = { 4e 4a [2] 6a 44 [2] 41 68 [2] 6f 4a [2] 7b 51 [2] 74 4b [2] 6a 56 [2] 68 57 [2] 73 51 [2] 6f 56 [2] 73 79 }

  condition:
    any of them
}