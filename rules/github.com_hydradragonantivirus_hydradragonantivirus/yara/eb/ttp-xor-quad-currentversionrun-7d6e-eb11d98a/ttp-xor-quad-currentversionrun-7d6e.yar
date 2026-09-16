rule TTP_XOR_QUAD_CurrentVersionRun_7d6e {
  strings:
    $key_7d6e = { 2e 01 [2] 0a 0f [2] 21 23 [2] 0f 01 [2] 1b 1a [2] 14 00 [2] 0a 1d [2] 08 1c [2] 13 1a [2] 0f 1d [2] 13 32 }

  condition:
    any of them
}