rule TTP_XOR_QUAD_CurrentVersionRun_1d5e {
  strings:
    $key_1d5e = { 4e 31 [2] 6a 3f [2] 41 13 [2] 6f 31 [2] 7b 2a [2] 74 30 [2] 6a 2d [2] 68 2c [2] 73 2a [2] 6f 2d [2] 73 02 }

  condition:
    any of them
}