rule TTP_XOR_QUAD_CurrentVersionRun_6647 {
  strings:
    $key_6647 = { 35 28 [2] 11 26 [2] 3a 0a [2] 14 28 [2] 00 33 [2] 0f 29 [2] 11 34 [2] 13 35 [2] 08 33 [2] 14 34 [2] 08 1b }

  condition:
    any of them
}