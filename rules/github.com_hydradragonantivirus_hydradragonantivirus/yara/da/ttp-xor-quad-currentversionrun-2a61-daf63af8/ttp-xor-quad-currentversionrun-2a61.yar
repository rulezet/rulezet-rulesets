rule TTP_XOR_QUAD_CurrentVersionRun_2a61 {
  strings:
    $key_2a61 = { 79 0e [2] 5d 00 [2] 76 2c [2] 58 0e [2] 4c 15 [2] 43 0f [2] 5d 12 [2] 5f 13 [2] 44 15 [2] 58 12 [2] 44 3d }

  condition:
    any of them
}