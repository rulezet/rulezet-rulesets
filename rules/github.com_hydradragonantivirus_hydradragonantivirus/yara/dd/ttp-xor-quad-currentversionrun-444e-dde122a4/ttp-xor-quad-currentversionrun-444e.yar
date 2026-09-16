rule TTP_XOR_QUAD_CurrentVersionRun_444e {
  strings:
    $key_444e = { 17 21 [2] 33 2f [2] 18 03 [2] 36 21 [2] 22 3a [2] 2d 20 [2] 33 3d [2] 31 3c [2] 2a 3a [2] 36 3d [2] 2a 12 }

  condition:
    any of them
}