rule TTP_XOR_QUAD_CurrentVersionRun_e743 {
  strings:
    $key_e743 = { b4 2c [2] 90 22 [2] bb 0e [2] 95 2c [2] 81 37 [2] 8e 2d [2] 90 30 [2] 92 31 [2] 89 37 [2] 95 30 [2] 89 1f }

  condition:
    any of them
}