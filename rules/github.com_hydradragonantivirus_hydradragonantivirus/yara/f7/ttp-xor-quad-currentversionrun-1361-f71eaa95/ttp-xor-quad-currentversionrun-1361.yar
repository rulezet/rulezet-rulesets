rule TTP_XOR_QUAD_CurrentVersionRun_1361 {
  strings:
    $key_1361 = { 40 0e [2] 64 00 [2] 4f 2c [2] 61 0e [2] 75 15 [2] 7a 0f [2] 64 12 [2] 66 13 [2] 7d 15 [2] 61 12 [2] 7d 3d }

  condition:
    any of them
}