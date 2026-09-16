rule TTP_XOR_QUAD_CurrentVersionRun_e769 {
  strings:
    $key_e769 = { b4 06 [2] 90 08 [2] bb 24 [2] 95 06 [2] 81 1d [2] 8e 07 [2] 90 1a [2] 92 1b [2] 89 1d [2] 95 1a [2] 89 35 }

  condition:
    any of them
}