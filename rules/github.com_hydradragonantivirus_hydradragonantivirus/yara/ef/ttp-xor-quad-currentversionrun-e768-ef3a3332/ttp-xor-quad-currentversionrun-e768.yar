rule TTP_XOR_QUAD_CurrentVersionRun_e768 {
  strings:
    $key_e768 = { b4 07 [2] 90 09 [2] bb 25 [2] 95 07 [2] 81 1c [2] 8e 06 [2] 90 1b [2] 92 1a [2] 89 1c [2] 95 1b [2] 89 34 }

  condition:
    any of them
}