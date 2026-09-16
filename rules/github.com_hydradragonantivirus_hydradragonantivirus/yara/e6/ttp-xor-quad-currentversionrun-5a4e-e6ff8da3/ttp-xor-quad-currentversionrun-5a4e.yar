rule TTP_XOR_QUAD_CurrentVersionRun_5a4e {
  strings:
    $key_5a4e = { 09 21 [2] 2d 2f [2] 06 03 [2] 28 21 [2] 3c 3a [2] 33 20 [2] 2d 3d [2] 2f 3c [2] 34 3a [2] 28 3d [2] 34 12 }

  condition:
    any of them
}