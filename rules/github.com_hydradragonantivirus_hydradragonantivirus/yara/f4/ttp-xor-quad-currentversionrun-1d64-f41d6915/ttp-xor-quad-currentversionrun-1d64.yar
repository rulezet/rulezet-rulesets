rule TTP_XOR_QUAD_CurrentVersionRun_1d64 {
  strings:
    $key_1d64 = { 4e 0b [2] 6a 05 [2] 41 29 [2] 6f 0b [2] 7b 10 [2] 74 0a [2] 6a 17 [2] 68 16 [2] 73 10 [2] 6f 17 [2] 73 38 }

  condition:
    any of them
}