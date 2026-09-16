rule TTP_XOR_QUAD_CurrentVersionRun_741d {
  strings:
    $key_741d = { 27 72 [2] 03 7c [2] 28 50 [2] 06 72 [2] 12 69 [2] 1d 73 [2] 03 6e [2] 01 6f [2] 1a 69 [2] 06 6e [2] 1a 41 }

  condition:
    any of them
}