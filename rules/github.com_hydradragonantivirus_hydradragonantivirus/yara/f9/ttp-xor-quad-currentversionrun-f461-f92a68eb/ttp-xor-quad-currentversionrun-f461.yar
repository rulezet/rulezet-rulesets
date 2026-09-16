rule TTP_XOR_QUAD_CurrentVersionRun_f461 {
  strings:
    $key_f461 = { a7 0e [2] 83 00 [2] a8 2c [2] 86 0e [2] 92 15 [2] 9d 0f [2] 83 12 [2] 81 13 [2] 9a 15 [2] 86 12 [2] 9a 3d }

  condition:
    any of them
}