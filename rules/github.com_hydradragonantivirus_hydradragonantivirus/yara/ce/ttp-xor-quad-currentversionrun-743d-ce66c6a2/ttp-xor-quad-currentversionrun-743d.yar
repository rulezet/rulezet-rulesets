rule TTP_XOR_QUAD_CurrentVersionRun_743d {
  strings:
    $key_743d = { 27 52 [2] 03 5c [2] 28 70 [2] 06 52 [2] 12 49 [2] 1d 53 [2] 03 4e [2] 01 4f [2] 1a 49 [2] 06 4e [2] 1a 61 }

  condition:
    any of them
}