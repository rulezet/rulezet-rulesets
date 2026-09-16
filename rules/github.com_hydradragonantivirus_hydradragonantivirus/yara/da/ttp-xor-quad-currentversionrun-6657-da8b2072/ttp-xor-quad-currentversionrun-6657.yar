rule TTP_XOR_QUAD_CurrentVersionRun_6657 {
  strings:
    $key_6657 = { 35 38 [2] 11 36 [2] 3a 1a [2] 14 38 [2] 00 23 [2] 0f 39 [2] 11 24 [2] 13 25 [2] 08 23 [2] 14 24 [2] 08 0b }

  condition:
    any of them
}