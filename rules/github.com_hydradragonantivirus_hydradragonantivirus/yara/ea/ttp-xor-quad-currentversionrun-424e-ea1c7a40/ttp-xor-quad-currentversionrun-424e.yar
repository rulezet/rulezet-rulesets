rule TTP_XOR_QUAD_CurrentVersionRun_424e {
  strings:
    $key_424e = { 11 21 [2] 35 2f [2] 1e 03 [2] 30 21 [2] 24 3a [2] 2b 20 [2] 35 3d [2] 37 3c [2] 2c 3a [2] 30 3d [2] 2c 12 }

  condition:
    any of them
}