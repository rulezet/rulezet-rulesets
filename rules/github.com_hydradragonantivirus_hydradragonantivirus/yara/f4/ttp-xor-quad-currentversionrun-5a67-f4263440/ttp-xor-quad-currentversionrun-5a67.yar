rule TTP_XOR_QUAD_CurrentVersionRun_5a67 {
  strings:
    $key_5a67 = { 09 08 [2] 2d 06 [2] 06 2a [2] 28 08 [2] 3c 13 [2] 33 09 [2] 2d 14 [2] 2f 15 [2] 34 13 [2] 28 14 [2] 34 3b }

  condition:
    any of them
}