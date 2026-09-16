rule TTP_XOR_QUAD_CurrentVersionRun_5d4e {
  strings:
    $key_5d4e = { 0e 21 [2] 2a 2f [2] 01 03 [2] 2f 21 [2] 3b 3a [2] 34 20 [2] 2a 3d [2] 28 3c [2] 33 3a [2] 2f 3d [2] 33 12 }

  condition:
    any of them
}