rule TTP_XOR_QUAD_CurrentVersionRun_436e {
  strings:
    $key_436e = { 10 01 [2] 34 0f [2] 1f 23 [2] 31 01 [2] 25 1a [2] 2a 00 [2] 34 1d [2] 36 1c [2] 2d 1a [2] 31 1d [2] 2d 32 }

  condition:
    any of them
}