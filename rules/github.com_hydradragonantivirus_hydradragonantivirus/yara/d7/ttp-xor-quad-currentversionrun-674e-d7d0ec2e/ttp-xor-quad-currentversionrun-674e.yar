rule TTP_XOR_QUAD_CurrentVersionRun_674e {
  strings:
    $key_674e = { 34 21 [2] 10 2f [2] 3b 03 [2] 15 21 [2] 01 3a [2] 0e 20 [2] 10 3d [2] 12 3c [2] 09 3a [2] 15 3d [2] 09 12 }

  condition:
    any of them
}