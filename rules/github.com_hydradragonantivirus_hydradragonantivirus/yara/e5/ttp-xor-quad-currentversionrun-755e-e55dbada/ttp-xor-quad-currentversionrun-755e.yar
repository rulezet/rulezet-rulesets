rule TTP_XOR_QUAD_CurrentVersionRun_755e {
  strings:
    $key_755e = { 26 31 [2] 02 3f [2] 29 13 [2] 07 31 [2] 13 2a [2] 1c 30 [2] 02 2d [2] 00 2c [2] 1b 2a [2] 07 2d [2] 1b 02 }

  condition:
    any of them
}