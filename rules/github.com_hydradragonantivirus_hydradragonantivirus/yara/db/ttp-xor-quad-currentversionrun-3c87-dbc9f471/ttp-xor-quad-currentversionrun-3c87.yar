rule TTP_XOR_QUAD_CurrentVersionRun_3c87 {
  strings:
    $key_3c87 = { 6f e8 [2] 4b e6 [2] 60 ca [2] 4e e8 [2] 5a f3 [2] 55 e9 [2] 4b f4 [2] 49 f5 [2] 52 f3 [2] 4e f4 [2] 52 db }

  condition:
    any of them
}