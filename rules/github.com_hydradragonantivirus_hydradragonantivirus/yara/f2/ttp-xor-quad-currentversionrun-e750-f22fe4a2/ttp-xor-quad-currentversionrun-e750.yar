rule TTP_XOR_QUAD_CurrentVersionRun_e750 {
  strings:
    $key_e750 = { b4 3f [2] 90 31 [2] bb 1d [2] 95 3f [2] 81 24 [2] 8e 3e [2] 90 23 [2] 92 22 [2] 89 24 [2] 95 23 [2] 89 0c }

  condition:
    any of them
}