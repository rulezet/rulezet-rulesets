rule TTP_XOR_QUAD_CurrentVersionRun_e06e {
  strings:
    $key_e06e = { b3 01 [2] 97 0f [2] bc 23 [2] 92 01 [2] 86 1a [2] 89 00 [2] 97 1d [2] 95 1c [2] 8e 1a [2] 92 1d [2] 8e 32 }

  condition:
    any of them
}