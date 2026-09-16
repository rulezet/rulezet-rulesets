rule TTP_XOR_QUAD_CurrentVersionRun_0987 {
  strings:
    $key_0987 = { 5a e8 [2] 7e e6 [2] 55 ca [2] 7b e8 [2] 6f f3 [2] 60 e9 [2] 7e f4 [2] 7c f5 [2] 67 f3 [2] 7b f4 [2] 67 db }

  condition:
    any of them
}