rule TTP_XOR_QUAD_CurrentVersionRun_2a6e {
  strings:
    $key_2a6e = { 79 01 [2] 5d 0f [2] 76 23 [2] 58 01 [2] 4c 1a [2] 43 00 [2] 5d 1d [2] 5f 1c [2] 44 1a [2] 58 1d [2] 44 32 }

  condition:
    any of them
}