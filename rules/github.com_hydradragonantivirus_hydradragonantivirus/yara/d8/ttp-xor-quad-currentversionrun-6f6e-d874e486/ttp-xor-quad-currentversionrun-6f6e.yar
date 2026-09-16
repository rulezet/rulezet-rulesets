rule TTP_XOR_QUAD_CurrentVersionRun_6f6e {
  strings:
    $key_6f6e = { 3c 01 [2] 18 0f [2] 33 23 [2] 1d 01 [2] 09 1a [2] 06 00 [2] 18 1d [2] 1a 1c [2] 01 1a [2] 1d 1d [2] 01 32 }

  condition:
    any of them
}