rule TTP_XOR_QUAD_CurrentVersionRun_744e {
  strings:
    $key_744e = { 27 21 [2] 03 2f [2] 28 03 [2] 06 21 [2] 12 3a [2] 1d 20 [2] 03 3d [2] 01 3c [2] 1a 3a [2] 06 3d [2] 1a 12 }

  condition:
    any of them
}