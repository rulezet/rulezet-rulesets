rule TTP_XOR_QUAD_CurrentVersionRun_7404 {
  strings:
    $key_7404 = { 27 6b [2] 03 65 [2] 28 49 [2] 06 6b [2] 12 70 [2] 1d 6a [2] 03 77 [2] 01 76 [2] 1a 70 [2] 06 77 [2] 1a 58 }

  condition:
    any of them
}