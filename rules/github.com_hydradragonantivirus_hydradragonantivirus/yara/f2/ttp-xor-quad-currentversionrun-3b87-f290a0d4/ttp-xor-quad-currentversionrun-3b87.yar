rule TTP_XOR_QUAD_CurrentVersionRun_3b87 {
  strings:
    $key_3b87 = { 68 e8 [2] 4c e6 [2] 67 ca [2] 49 e8 [2] 5d f3 [2] 52 e9 [2] 4c f4 [2] 4e f5 [2] 55 f3 [2] 49 f4 [2] 55 db }

  condition:
    any of them
}