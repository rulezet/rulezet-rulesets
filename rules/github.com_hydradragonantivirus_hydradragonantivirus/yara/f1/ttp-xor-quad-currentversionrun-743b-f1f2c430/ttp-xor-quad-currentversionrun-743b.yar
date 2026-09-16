rule TTP_XOR_QUAD_CurrentVersionRun_743b {
  strings:
    $key_743b = { 27 54 [2] 03 5a [2] 28 76 [2] 06 54 [2] 12 4f [2] 1d 55 [2] 03 48 [2] 01 49 [2] 1a 4f [2] 06 48 [2] 1a 67 }

  condition:
    any of them
}