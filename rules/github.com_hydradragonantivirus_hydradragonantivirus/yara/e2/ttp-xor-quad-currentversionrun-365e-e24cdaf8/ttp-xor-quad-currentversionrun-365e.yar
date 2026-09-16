rule TTP_XOR_QUAD_CurrentVersionRun_365e {
  strings:
    $key_365e = { 65 31 [2] 41 3f [2] 6a 13 [2] 44 31 [2] 50 2a [2] 5f 30 [2] 41 2d [2] 43 2c [2] 58 2a [2] 44 2d [2] 58 02 }

  condition:
    any of them
}