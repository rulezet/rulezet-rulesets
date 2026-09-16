rule TTP_XOR_QUAD_CurrentVersionRun_425e {
  strings:
    $key_425e = { 11 31 [2] 35 3f [2] 1e 13 [2] 30 31 [2] 24 2a [2] 2b 30 [2] 35 2d [2] 37 2c [2] 2c 2a [2] 30 2d [2] 2c 02 }

  condition:
    any of them
}