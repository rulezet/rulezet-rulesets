rule TTP_XOR_QUAD_CurrentVersionRun_1261 {
  strings:
    $key_1261 = { 41 0e [2] 65 00 [2] 4e 2c [2] 60 0e [2] 74 15 [2] 7b 0f [2] 65 12 [2] 67 13 [2] 7c 15 [2] 60 12 [2] 7c 3d }

  condition:
    any of them
}