rule TTP_XOR_QUAD_CurrentVersionRun_737b {
  strings:
    $key_737b = { 20 14 [2] 04 1a [2] 2f 36 [2] 01 14 [2] 15 0f [2] 1a 15 [2] 04 08 [2] 06 09 [2] 1d 0f [2] 01 08 [2] 1d 27 }

  condition:
    any of them
}