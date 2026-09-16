rule TTP_XOR_QUAD_CurrentVersionRun_4e5e {
  strings:
    $key_4e5e = { 1d 31 [2] 39 3f [2] 12 13 [2] 3c 31 [2] 28 2a [2] 27 30 [2] 39 2d [2] 3b 2c [2] 20 2a [2] 3c 2d [2] 20 02 }

  condition:
    any of them
}