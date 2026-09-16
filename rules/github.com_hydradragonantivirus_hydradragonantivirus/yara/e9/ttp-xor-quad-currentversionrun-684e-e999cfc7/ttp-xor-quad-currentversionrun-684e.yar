rule TTP_XOR_QUAD_CurrentVersionRun_684e {
  strings:
    $key_684e = { 3b 21 [2] 1f 2f [2] 34 03 [2] 1a 21 [2] 0e 3a [2] 01 20 [2] 1f 3d [2] 1d 3c [2] 06 3a [2] 1a 3d [2] 06 12 }

  condition:
    any of them
}