rule TTP_XOR_QUAD_CurrentVersionRun_404e {
  strings:
    $key_404e = { 13 21 [2] 37 2f [2] 1c 03 [2] 32 21 [2] 26 3a [2] 29 20 [2] 37 3d [2] 35 3c [2] 2e 3a [2] 32 3d [2] 2e 12 }

  condition:
    any of them
}