rule TTP_XOR_QUAD_CurrentVersionRun_6447 {
  strings:
    $key_6447 = { 37 28 [2] 13 26 [2] 38 0a [2] 16 28 [2] 02 33 [2] 0d 29 [2] 13 34 [2] 11 35 [2] 0a 33 [2] 16 34 [2] 0a 1b }

  condition:
    any of them
}