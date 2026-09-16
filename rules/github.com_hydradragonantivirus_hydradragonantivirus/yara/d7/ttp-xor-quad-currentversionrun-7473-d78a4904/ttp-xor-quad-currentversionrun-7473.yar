rule TTP_XOR_QUAD_CurrentVersionRun_7473 {
  strings:
    $key_7473 = { 27 1c [2] 03 12 [2] 28 3e [2] 06 1c [2] 12 07 [2] 1d 1d [2] 03 00 [2] 01 01 [2] 1a 07 [2] 06 00 [2] 1a 2f }

  condition:
    any of them
}