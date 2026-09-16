rule TTP_XOR_QUAD_CurrentVersionRun_505e {
  strings:
    $key_505e = { 03 31 [2] 27 3f [2] 0c 13 [2] 22 31 [2] 36 2a [2] 39 30 [2] 27 2d [2] 25 2c [2] 3e 2a [2] 22 2d [2] 3e 02 }

  condition:
    any of them
}