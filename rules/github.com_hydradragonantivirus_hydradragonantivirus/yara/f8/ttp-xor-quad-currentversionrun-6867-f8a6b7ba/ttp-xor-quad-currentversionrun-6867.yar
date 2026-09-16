rule TTP_XOR_QUAD_CurrentVersionRun_6867 {
  strings:
    $key_6867 = { 3b 08 [2] 1f 06 [2] 34 2a [2] 1a 08 [2] 0e 13 [2] 01 09 [2] 1f 14 [2] 1d 15 [2] 06 13 [2] 1a 14 [2] 06 3b }

  condition:
    any of them
}