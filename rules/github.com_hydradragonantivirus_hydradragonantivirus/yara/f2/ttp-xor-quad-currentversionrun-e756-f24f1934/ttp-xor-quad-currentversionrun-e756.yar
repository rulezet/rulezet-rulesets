rule TTP_XOR_QUAD_CurrentVersionRun_e756 {
  strings:
    $key_e756 = { b4 39 [2] 90 37 [2] bb 1b [2] 95 39 [2] 81 22 [2] 8e 38 [2] 90 25 [2] 92 24 [2] 89 22 [2] 95 25 [2] 89 0a }

  condition:
    any of them
}