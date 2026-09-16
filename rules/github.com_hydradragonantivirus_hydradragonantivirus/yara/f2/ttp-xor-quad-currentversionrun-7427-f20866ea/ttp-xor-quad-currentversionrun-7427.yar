rule TTP_XOR_QUAD_CurrentVersionRun_7427 {
  strings:
    $key_7427 = { 27 48 [2] 03 46 [2] 28 6a [2] 06 48 [2] 12 53 [2] 1d 49 [2] 03 54 [2] 01 55 [2] 1a 53 [2] 06 54 [2] 1a 7b }

  condition:
    any of them
}