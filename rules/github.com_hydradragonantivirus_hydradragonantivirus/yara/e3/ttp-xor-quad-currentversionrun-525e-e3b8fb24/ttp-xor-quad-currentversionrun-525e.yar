rule TTP_XOR_QUAD_CurrentVersionRun_525e {
  strings:
    $key_525e = { 01 31 [2] 25 3f [2] 0e 13 [2] 20 31 [2] 34 2a [2] 3b 30 [2] 25 2d [2] 27 2c [2] 3c 2a [2] 20 2d [2] 3c 02 }

  condition:
    any of them
}