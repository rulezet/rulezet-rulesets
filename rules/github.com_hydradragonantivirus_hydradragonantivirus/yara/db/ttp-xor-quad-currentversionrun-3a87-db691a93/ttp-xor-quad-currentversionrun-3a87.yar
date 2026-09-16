rule TTP_XOR_QUAD_CurrentVersionRun_3a87 {
  strings:
    $key_3a87 = { 69 e8 [2] 4d e6 [2] 66 ca [2] 48 e8 [2] 5c f3 [2] 53 e9 [2] 4d f4 [2] 4f f5 [2] 54 f3 [2] 48 f4 [2] 54 db }

  condition:
    any of them
}