rule TTP_XOR_QUAD_CurrentVersionRun_4667 {
  strings:
    $key_4667 = { 15 08 [2] 31 06 [2] 1a 2a [2] 34 08 [2] 20 13 [2] 2f 09 [2] 31 14 [2] 33 15 [2] 28 13 [2] 34 14 [2] 28 3b }

  condition:
    any of them
}