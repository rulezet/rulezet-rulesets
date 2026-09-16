rule TTP_XOR_QUAD_CurrentVersionRun_265e {
  strings:
    $key_265e = { 75 31 [2] 51 3f [2] 7a 13 [2] 54 31 [2] 40 2a [2] 4f 30 [2] 51 2d [2] 53 2c [2] 48 2a [2] 54 2d [2] 48 02 }

  condition:
    any of them
}