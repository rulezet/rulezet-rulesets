rule TTP_XOR_QUAD_CurrentVersionRun_2d6e {
  strings:
    $key_2d6e = { 7e 01 [2] 5a 0f [2] 71 23 [2] 5f 01 [2] 4b 1a [2] 44 00 [2] 5a 1d [2] 58 1c [2] 43 1a [2] 5f 1d [2] 43 32 }

  condition:
    any of them
}