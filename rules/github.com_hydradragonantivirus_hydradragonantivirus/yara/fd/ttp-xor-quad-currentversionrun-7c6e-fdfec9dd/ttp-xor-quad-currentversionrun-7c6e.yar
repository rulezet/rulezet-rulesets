rule TTP_XOR_QUAD_CurrentVersionRun_7c6e {
  strings:
    $key_7c6e = { 2f 01 [2] 0b 0f [2] 20 23 [2] 0e 01 [2] 1a 1a [2] 15 00 [2] 0b 1d [2] 09 1c [2] 12 1a [2] 0e 1d [2] 12 32 }

  condition:
    any of them
}