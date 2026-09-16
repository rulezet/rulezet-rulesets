rule TTP_XOR_QUAD_CurrentVersionRun_0f87 {
  strings:
    $key_0f87 = { 5c e8 [2] 78 e6 [2] 53 ca [2] 7d e8 [2] 69 f3 [2] 66 e9 [2] 78 f4 [2] 7a f5 [2] 61 f3 [2] 7d f4 [2] 61 db }

  condition:
    any of them
}