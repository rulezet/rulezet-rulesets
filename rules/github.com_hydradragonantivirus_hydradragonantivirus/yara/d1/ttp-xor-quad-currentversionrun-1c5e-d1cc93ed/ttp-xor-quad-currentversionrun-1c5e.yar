rule TTP_XOR_QUAD_CurrentVersionRun_1c5e {
  strings:
    $key_1c5e = { 4f 31 [2] 6b 3f [2] 40 13 [2] 6e 31 [2] 7a 2a [2] 75 30 [2] 6b 2d [2] 69 2c [2] 72 2a [2] 6e 2d [2] 72 02 }

  condition:
    any of them
}