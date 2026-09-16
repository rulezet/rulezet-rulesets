rule TTP_XOR_QUAD_CurrentVersionRun_6f19 {
  strings:
    $key_6f19 = { 3c 76 [2] 18 78 [2] 33 54 [2] 1d 76 [2] 09 6d [2] 06 77 [2] 18 6a [2] 1a 6b [2] 01 6d [2] 1d 6a [2] 01 45 }

  condition:
    any of them
}