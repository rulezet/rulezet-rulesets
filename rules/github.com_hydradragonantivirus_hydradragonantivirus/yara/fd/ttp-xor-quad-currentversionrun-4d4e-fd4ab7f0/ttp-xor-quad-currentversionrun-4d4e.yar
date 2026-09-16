rule TTP_XOR_QUAD_CurrentVersionRun_4d4e {
  strings:
    $key_4d4e = { 1e 21 [2] 3a 2f [2] 11 03 [2] 3f 21 [2] 2b 3a [2] 24 20 [2] 3a 3d [2] 38 3c [2] 23 3a [2] 3f 3d [2] 23 12 }

  condition:
    any of them
}