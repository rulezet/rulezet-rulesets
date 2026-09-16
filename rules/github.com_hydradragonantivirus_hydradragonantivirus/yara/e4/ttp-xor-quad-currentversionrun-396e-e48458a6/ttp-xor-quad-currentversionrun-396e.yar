rule TTP_XOR_QUAD_CurrentVersionRun_396e {
  strings:
    $key_396e = { 6a 01 [2] 4e 0f [2] 65 23 [2] 4b 01 [2] 5f 1a [2] 50 00 [2] 4e 1d [2] 4c 1c [2] 57 1a [2] 4b 1d [2] 57 32 }

  condition:
    any of them
}