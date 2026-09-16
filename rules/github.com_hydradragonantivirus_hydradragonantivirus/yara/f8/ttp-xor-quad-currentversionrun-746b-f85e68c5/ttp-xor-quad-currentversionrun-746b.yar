rule TTP_XOR_QUAD_CurrentVersionRun_746b {
  strings:
    $key_746b = { 27 04 [2] 03 0a [2] 28 26 [2] 06 04 [2] 12 1f [2] 1d 05 [2] 03 18 [2] 01 19 [2] 1a 1f [2] 06 18 [2] 1a 37 }

  condition:
    any of them
}