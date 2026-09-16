rule TTP_XOR_QUAD_CurrentVersionRun_e861 {
  strings:
    $key_e861 = { bb 0e [2] 9f 00 [2] b4 2c [2] 9a 0e [2] 8e 15 [2] 81 0f [2] 9f 12 [2] 9d 13 [2] 86 15 [2] 9a 12 [2] 86 3d }

  condition:
    any of them
}