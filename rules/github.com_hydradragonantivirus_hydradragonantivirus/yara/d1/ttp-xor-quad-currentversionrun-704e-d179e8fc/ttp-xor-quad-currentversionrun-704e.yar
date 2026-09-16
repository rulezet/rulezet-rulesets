rule TTP_XOR_QUAD_CurrentVersionRun_704e {
  strings:
    $key_704e = { 23 21 [2] 07 2f [2] 2c 03 [2] 02 21 [2] 16 3a [2] 19 20 [2] 07 3d [2] 05 3c [2] 1e 3a [2] 02 3d [2] 1e 12 }

  condition:
    any of them
}