rule TTP_XOR_QUAD_CurrentVersionRun_7401 {
  strings:
    $key_7401 = { 27 6e [2] 03 60 [2] 28 4c [2] 06 6e [2] 12 75 [2] 1d 6f [2] 03 72 [2] 01 73 [2] 1a 75 [2] 06 72 [2] 1a 5d }

  condition:
    any of them
}