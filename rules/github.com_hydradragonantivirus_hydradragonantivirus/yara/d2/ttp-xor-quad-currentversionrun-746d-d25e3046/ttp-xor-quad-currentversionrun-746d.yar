rule TTP_XOR_QUAD_CurrentVersionRun_746d {
  strings:
    $key_746d = { 27 02 [2] 03 0c [2] 28 20 [2] 06 02 [2] 12 19 [2] 1d 03 [2] 03 1e [2] 01 1f [2] 1a 19 [2] 06 1e [2] 1a 31 }

  condition:
    any of them
}