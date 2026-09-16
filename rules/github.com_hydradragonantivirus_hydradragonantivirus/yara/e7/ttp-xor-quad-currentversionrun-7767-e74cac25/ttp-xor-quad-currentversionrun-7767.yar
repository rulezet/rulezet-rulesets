rule TTP_XOR_QUAD_CurrentVersionRun_7767 {
  strings:
    $key_7767 = { 24 08 [2] 00 06 [2] 2b 2a [2] 05 08 [2] 11 13 [2] 1e 09 [2] 00 14 [2] 02 15 [2] 19 13 [2] 05 14 [2] 19 3b }

  condition:
    any of them
}