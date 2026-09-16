rule TTP_XOR_QUAD_CurrentVersionRun_7448 {
  strings:
    $key_7448 = { 27 27 [2] 03 29 [2] 28 05 [2] 06 27 [2] 12 3c [2] 1d 26 [2] 03 3b [2] 01 3a [2] 1a 3c [2] 06 3b [2] 1a 14 }

  condition:
    any of them
}