rule TTP_XOR_QUAD_CurrentVersionRun_4e4e {
  strings:
    $key_4e4e = { 1d 21 [2] 39 2f [2] 12 03 [2] 3c 21 [2] 28 3a [2] 27 20 [2] 39 3d [2] 3b 3c [2] 20 3a [2] 3c 3d [2] 20 12 }

  condition:
    any of them
}