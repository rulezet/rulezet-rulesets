rule TTP_XOR_QUAD_CurrentVersionRun_7462 {
  strings:
    $key_7462 = { 27 0d [2] 03 03 [2] 28 2f [2] 06 0d [2] 12 16 [2] 1d 0c [2] 03 11 [2] 01 10 [2] 1a 16 [2] 06 11 [2] 1a 3e }

  condition:
    any of them
}