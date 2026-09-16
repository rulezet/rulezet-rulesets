rule TTP_XOR_QUAD_CurrentVersionRun_1f87 {
  strings:
    $key_1f87 = { 4c e8 [2] 68 e6 [2] 43 ca [2] 6d e8 [2] 79 f3 [2] 76 e9 [2] 68 f4 [2] 6a f5 [2] 71 f3 [2] 6d f4 [2] 71 db }

  condition:
    any of them
}