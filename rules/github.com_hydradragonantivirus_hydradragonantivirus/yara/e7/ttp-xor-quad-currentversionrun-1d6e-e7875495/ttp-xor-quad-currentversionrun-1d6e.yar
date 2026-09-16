rule TTP_XOR_QUAD_CurrentVersionRun_1d6e {
  strings:
    $key_1d6e = { 4e 01 [2] 6a 0f [2] 41 23 [2] 6f 01 [2] 7b 1a [2] 74 00 [2] 6a 1d [2] 68 1c [2] 73 1a [2] 6f 1d [2] 73 32 }

  condition:
    any of them
}