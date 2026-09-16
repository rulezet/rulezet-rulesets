rule TTP_XOR_QUAD_CurrentVersionRun_6b87 {
  strings:
    $key_6b87 = { 38 e8 [2] 1c e6 [2] 37 ca [2] 19 e8 [2] 0d f3 [2] 02 e9 [2] 1c f4 [2] 1e f5 [2] 05 f3 [2] 19 f4 [2] 05 db }

  condition:
    any of them
}