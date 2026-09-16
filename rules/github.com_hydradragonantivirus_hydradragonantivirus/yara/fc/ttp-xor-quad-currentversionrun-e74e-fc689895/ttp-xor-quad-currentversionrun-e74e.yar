rule TTP_XOR_QUAD_CurrentVersionRun_e74e {
  strings:
    $key_e74e = { b4 21 [2] 90 2f [2] bb 03 [2] 95 21 [2] 81 3a [2] 8e 20 [2] 90 3d [2] 92 3c [2] 89 3a [2] 95 3d [2] 89 12 }

  condition:
    any of them
}