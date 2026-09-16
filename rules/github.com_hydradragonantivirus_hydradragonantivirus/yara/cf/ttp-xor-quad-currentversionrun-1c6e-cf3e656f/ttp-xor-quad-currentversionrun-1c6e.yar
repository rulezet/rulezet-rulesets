rule TTP_XOR_QUAD_CurrentVersionRun_1c6e {
  strings:
    $key_1c6e = { 4f 01 [2] 6b 0f [2] 40 23 [2] 6e 01 [2] 7a 1a [2] 75 00 [2] 6b 1d [2] 69 1c [2] 72 1a [2] 6e 1d [2] 72 32 }

  condition:
    any of them
}