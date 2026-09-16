rule TTP_XOR_QUAD_CurrentVersionRun_415e {
  strings:
    $key_415e = { 12 31 [2] 36 3f [2] 1d 13 [2] 33 31 [2] 27 2a [2] 28 30 [2] 36 2d [2] 34 2c [2] 2f 2a [2] 33 2d [2] 2f 02 }

  condition:
    any of them
}