rule TTP_XOR_QUAD_CurrentVersionRun_740b {
  strings:
    $key_740b = { 27 64 [2] 03 6a [2] 28 46 [2] 06 64 [2] 12 7f [2] 1d 65 [2] 03 78 [2] 01 79 [2] 1a 7f [2] 06 78 [2] 1a 57 }

  condition:
    any of them
}