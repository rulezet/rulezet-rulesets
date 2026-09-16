rule TTP_XOR_QUAD_CurrentVersionRun_e761 {
  strings:
    $key_e761 = { b4 0e [2] 90 00 [2] bb 2c [2] 95 0e [2] 81 15 [2] 8e 0f [2] 90 12 [2] 92 13 [2] 89 15 [2] 95 12 [2] 89 3d }

  condition:
    any of them
}