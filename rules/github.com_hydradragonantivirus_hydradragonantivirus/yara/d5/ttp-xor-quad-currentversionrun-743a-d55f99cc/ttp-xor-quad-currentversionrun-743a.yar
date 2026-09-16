rule TTP_XOR_QUAD_CurrentVersionRun_743a {
  strings:
    $key_743a = { 27 55 [2] 03 5b [2] 28 77 [2] 06 55 [2] 12 4e [2] 1d 54 [2] 03 49 [2] 01 48 [2] 1a 4e [2] 06 49 [2] 1a 66 }

  condition:
    any of them
}