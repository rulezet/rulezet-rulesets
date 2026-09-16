rule TTP_XOR_QUAD_CurrentVersionRun_315e {
  strings:
    $key_315e = { 62 31 [2] 46 3f [2] 6d 13 [2] 43 31 [2] 57 2a [2] 58 30 [2] 46 2d [2] 44 2c [2] 5f 2a [2] 43 2d [2] 5f 02 }

  condition:
    any of them
}