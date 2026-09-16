rule TTP_XOR_QUAD_CurrentVersionRun_7887 {
  strings:
    $key_7887 = { 2b e8 [2] 0f e6 [2] 24 ca [2] 0a e8 [2] 1e f3 [2] 11 e9 [2] 0f f4 [2] 0d f5 [2] 16 f3 [2] 0a f4 [2] 16 db }

  condition:
    any of them
}