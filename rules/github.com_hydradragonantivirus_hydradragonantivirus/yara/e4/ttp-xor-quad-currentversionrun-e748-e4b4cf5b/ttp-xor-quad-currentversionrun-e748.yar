rule TTP_XOR_QUAD_CurrentVersionRun_e748 {
  strings:
    $key_e748 = { b4 27 [2] 90 29 [2] bb 05 [2] 95 27 [2] 81 3c [2] 8e 26 [2] 90 3b [2] 92 3a [2] 89 3c [2] 95 3b [2] 89 14 }

  condition:
    any of them
}