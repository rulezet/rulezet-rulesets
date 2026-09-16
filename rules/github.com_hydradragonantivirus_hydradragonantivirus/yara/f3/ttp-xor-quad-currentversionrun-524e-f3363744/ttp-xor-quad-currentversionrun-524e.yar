rule TTP_XOR_QUAD_CurrentVersionRun_524e {
  strings:
    $key_524e = { 01 21 [2] 25 2f [2] 0e 03 [2] 20 21 [2] 34 3a [2] 3b 20 [2] 25 3d [2] 27 3c [2] 3c 3a [2] 20 3d [2] 3c 12 }

  condition:
    any of them
}