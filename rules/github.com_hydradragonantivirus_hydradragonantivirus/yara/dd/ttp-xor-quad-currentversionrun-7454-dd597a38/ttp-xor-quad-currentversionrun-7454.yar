rule TTP_XOR_QUAD_CurrentVersionRun_7454 {
  strings:
    $key_7454 = { 27 3b [2] 03 35 [2] 28 19 [2] 06 3b [2] 12 20 [2] 1d 3a [2] 03 27 [2] 01 26 [2] 1a 20 [2] 06 27 [2] 1a 08 }

  condition:
    any of them
}