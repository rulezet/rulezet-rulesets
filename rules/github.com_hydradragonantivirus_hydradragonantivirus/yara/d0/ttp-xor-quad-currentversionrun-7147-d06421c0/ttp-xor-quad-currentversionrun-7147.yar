rule TTP_XOR_QUAD_CurrentVersionRun_7147 {
  strings:
    $key_7147 = { 22 28 [2] 06 26 [2] 2d 0a [2] 03 28 [2] 17 33 [2] 18 29 [2] 06 34 [2] 04 35 [2] 1f 33 [2] 03 34 [2] 1f 1b }

  condition:
    any of them
}