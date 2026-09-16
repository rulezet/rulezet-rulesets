rule TTP_XOR_QUAD_CurrentVersionRun_7c4e {
  strings:
    $key_7c4e = { 2f 21 [2] 0b 2f [2] 20 03 [2] 0e 21 [2] 1a 3a [2] 15 20 [2] 0b 3d [2] 09 3c [2] 12 3a [2] 0e 3d [2] 12 12 }

  condition:
    any of them
}