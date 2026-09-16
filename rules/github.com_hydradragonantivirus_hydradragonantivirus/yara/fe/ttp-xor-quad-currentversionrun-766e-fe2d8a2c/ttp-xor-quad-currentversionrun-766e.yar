rule TTP_XOR_QUAD_CurrentVersionRun_766e {
  strings:
    $key_766e = { 25 01 [2] 01 0f [2] 2a 23 [2] 04 01 [2] 10 1a [2] 1f 00 [2] 01 1d [2] 03 1c [2] 18 1a [2] 04 1d [2] 18 32 }

  condition:
    any of them
}