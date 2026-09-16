rule TTP_XOR_QUAD_CurrentVersionRun_5a73 {
  strings:
    $key_5a73 = { 09 1c [2] 2d 12 [2] 06 3e [2] 28 1c [2] 3c 07 [2] 33 1d [2] 2d 00 [2] 2f 01 [2] 34 07 [2] 28 00 [2] 34 2f }

  condition:
    any of them
}