rule TTP_XOR_QUAD_CurrentVersionRun_4c6e {
  strings:
    $key_4c6e = { 1f 01 [2] 3b 0f [2] 10 23 [2] 3e 01 [2] 2a 1a [2] 25 00 [2] 3b 1d [2] 39 1c [2] 22 1a [2] 3e 1d [2] 22 32 }

  condition:
    any of them
}