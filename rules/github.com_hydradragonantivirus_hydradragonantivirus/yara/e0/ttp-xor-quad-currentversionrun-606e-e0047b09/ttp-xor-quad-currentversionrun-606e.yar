rule TTP_XOR_QUAD_CurrentVersionRun_606e {
  strings:
    $key_606e = { 33 01 [2] 17 0f [2] 3c 23 [2] 12 01 [2] 06 1a [2] 09 00 [2] 17 1d [2] 15 1c [2] 0e 1a [2] 12 1d [2] 0e 32 }

  condition:
    any of them
}