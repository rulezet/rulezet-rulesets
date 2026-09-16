rule TTP_XOR_QUAD_CurrentVersionRun_6987 {
  strings:
    $key_6987 = { 3a e8 [2] 1e e6 [2] 35 ca [2] 1b e8 [2] 0f f3 [2] 00 e9 [2] 1e f4 [2] 1c f5 [2] 07 f3 [2] 1b f4 [2] 07 db }

  condition:
    any of them
}