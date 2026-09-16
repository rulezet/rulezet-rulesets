rule TTP_XOR_QUAD_CurrentVersionRun_7435 {
  strings:
    $key_7435 = { 27 5a [2] 03 54 [2] 28 78 [2] 06 5a [2] 12 41 [2] 1d 5b [2] 03 46 [2] 01 47 [2] 1a 41 [2] 06 46 [2] 1a 69 }

  condition:
    any of them
}