rule TTP_XOR_QUAD_CurrentVersionRun_e757 {
  strings:
    $key_e757 = { b4 38 [2] 90 36 [2] bb 1a [2] 95 38 [2] 81 23 [2] 8e 39 [2] 90 24 [2] 92 25 [2] 89 23 [2] 95 24 [2] 89 0b }

  condition:
    any of them
}