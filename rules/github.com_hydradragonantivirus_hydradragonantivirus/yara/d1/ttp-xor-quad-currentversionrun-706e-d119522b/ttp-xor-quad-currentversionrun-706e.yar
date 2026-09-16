rule TTP_XOR_QUAD_CurrentVersionRun_706e {
  strings:
    $key_706e = { 23 01 [2] 07 0f [2] 2c 23 [2] 02 01 [2] 16 1a [2] 19 00 [2] 07 1d [2] 05 1c [2] 1e 1a [2] 02 1d [2] 1e 32 }

  condition:
    any of them
}