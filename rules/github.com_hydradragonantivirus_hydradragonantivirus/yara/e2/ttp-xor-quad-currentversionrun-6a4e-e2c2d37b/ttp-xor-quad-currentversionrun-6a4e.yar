rule TTP_XOR_QUAD_CurrentVersionRun_6a4e {
  strings:
    $key_6a4e = { 39 21 [2] 1d 2f [2] 36 03 [2] 18 21 [2] 0c 3a [2] 03 20 [2] 1d 3d [2] 1f 3c [2] 04 3a [2] 18 3d [2] 04 12 }

  condition:
    any of them
}