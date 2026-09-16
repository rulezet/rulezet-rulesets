rule TTP_XOR_QUAD_CurrentVersionRun_5a87 {
  strings:
    $key_5a87 = { 09 e8 [2] 2d e6 [2] 06 ca [2] 28 e8 [2] 3c f3 [2] 33 e9 [2] 2d f4 [2] 2f f5 [2] 34 f3 [2] 28 f4 [2] 34 db }

  condition:
    any of them
}