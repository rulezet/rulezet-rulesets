rule TTP_XOR_QUAD_CurrentVersionRun_1d61 {
  strings:
    $key_1d61 = { 4e 0e [2] 6a 00 [2] 41 2c [2] 6f 0e [2] 7b 15 [2] 74 0f [2] 6a 12 [2] 68 13 [2] 73 15 [2] 6f 12 [2] 73 3d }

  condition:
    any of them
}