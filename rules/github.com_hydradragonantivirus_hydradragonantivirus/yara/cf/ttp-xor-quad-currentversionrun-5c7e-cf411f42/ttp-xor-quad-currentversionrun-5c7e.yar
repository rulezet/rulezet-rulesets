rule TTP_XOR_QUAD_CurrentVersionRun_5c7e {
  strings:
    $key_5c7e = { 0f 11 [2] 2b 1f [2] 00 33 [2] 2e 11 [2] 3a 0a [2] 35 10 [2] 2b 0d [2] 29 0c [2] 32 0a [2] 2e 0d [2] 32 22 }

  condition:
    any of them
}