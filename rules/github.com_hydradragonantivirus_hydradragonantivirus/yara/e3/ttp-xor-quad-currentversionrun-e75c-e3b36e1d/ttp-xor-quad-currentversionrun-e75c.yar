rule TTP_XOR_QUAD_CurrentVersionRun_e75c {
  strings:
    $key_e75c = { b4 33 [2] 90 3d [2] bb 11 [2] 95 33 [2] 81 28 [2] 8e 32 [2] 90 2f [2] 92 2e [2] 89 28 [2] 95 2f [2] 89 00 }

  condition:
    any of them
}