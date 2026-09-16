rule TTP_XOR_QUAD_CurrentVersionRun_6087 {
  strings:
    $key_6087 = { 33 e8 [2] 17 e6 [2] 3c ca [2] 12 e8 [2] 06 f3 [2] 09 e9 [2] 17 f4 [2] 15 f5 [2] 0e f3 [2] 12 f4 [2] 0e db }

  condition:
    any of them
}