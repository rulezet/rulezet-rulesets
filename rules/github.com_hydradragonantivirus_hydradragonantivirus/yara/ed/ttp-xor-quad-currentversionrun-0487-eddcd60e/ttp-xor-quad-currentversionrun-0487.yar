rule TTP_XOR_QUAD_CurrentVersionRun_0487 {
  strings:
    $key_0487 = { 57 e8 [2] 73 e6 [2] 58 ca [2] 76 e8 [2] 62 f3 [2] 6d e9 [2] 73 f4 [2] 71 f5 [2] 6a f3 [2] 76 f4 [2] 6a db }

  condition:
    any of them
}