rule TTP_XOR_QUAD_CurrentVersionRun_5c4e {
  strings:
    $key_5c4e = { 0f 21 [2] 2b 2f [2] 00 03 [2] 2e 21 [2] 3a 3a [2] 35 20 [2] 2b 3d [2] 29 3c [2] 32 3a [2] 2e 3d [2] 32 12 }

  condition:
    any of them
}