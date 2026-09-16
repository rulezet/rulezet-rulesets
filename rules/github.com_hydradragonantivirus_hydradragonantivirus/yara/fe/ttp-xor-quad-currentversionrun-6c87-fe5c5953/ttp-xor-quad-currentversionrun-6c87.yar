rule TTP_XOR_QUAD_CurrentVersionRun_6c87 {
  strings:
    $key_6c87 = { 3f e8 [2] 1b e6 [2] 30 ca [2] 1e e8 [2] 0a f3 [2] 05 e9 [2] 1b f4 [2] 19 f5 [2] 02 f3 [2] 1e f4 [2] 02 db }

  condition:
    any of them
}