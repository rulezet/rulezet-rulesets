rule TTP_XOR_QUAD_CurrentVersionRun_514e {
  strings:
    $key_514e = { 02 21 [2] 26 2f [2] 0d 03 [2] 23 21 [2] 37 3a [2] 38 20 [2] 26 3d [2] 24 3c [2] 3f 3a [2] 23 3d [2] 3f 12 }

  condition:
    any of them
}