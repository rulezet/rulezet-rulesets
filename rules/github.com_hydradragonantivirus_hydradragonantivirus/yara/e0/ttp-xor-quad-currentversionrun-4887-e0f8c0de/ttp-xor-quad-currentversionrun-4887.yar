rule TTP_XOR_QUAD_CurrentVersionRun_4887 {
  strings:
    $key_4887 = { 1b e8 [2] 3f e6 [2] 14 ca [2] 3a e8 [2] 2e f3 [2] 21 e9 [2] 3f f4 [2] 3d f5 [2] 26 f3 [2] 3a f4 [2] 26 db }

  condition:
    any of them
}