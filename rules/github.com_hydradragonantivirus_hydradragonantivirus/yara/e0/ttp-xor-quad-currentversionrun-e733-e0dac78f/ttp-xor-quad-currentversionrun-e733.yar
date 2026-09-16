rule TTP_XOR_QUAD_CurrentVersionRun_e733 {
  strings:
    $key_e733 = { b4 5c [2] 90 52 [2] bb 7e [2] 95 5c [2] 81 47 [2] 8e 5d [2] 90 40 [2] 92 41 [2] 89 47 [2] 95 40 [2] 89 6f }

  condition:
    any of them
}