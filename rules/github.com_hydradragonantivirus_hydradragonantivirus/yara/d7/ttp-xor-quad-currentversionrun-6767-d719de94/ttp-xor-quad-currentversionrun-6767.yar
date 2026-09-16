rule TTP_XOR_QUAD_CurrentVersionRun_6767 {
  strings:
    $key_6767 = { 34 08 [2] 10 06 [2] 3b 2a [2] 15 08 [2] 01 13 [2] 0e 09 [2] 10 14 [2] 12 15 [2] 09 13 [2] 15 14 [2] 09 3b }

  condition:
    any of them
}