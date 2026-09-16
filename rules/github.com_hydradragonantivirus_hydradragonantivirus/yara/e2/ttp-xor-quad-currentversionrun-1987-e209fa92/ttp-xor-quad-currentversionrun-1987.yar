rule TTP_XOR_QUAD_CurrentVersionRun_1987 {
  strings:
    $key_1987 = { 4a e8 [2] 6e e6 [2] 45 ca [2] 6b e8 [2] 7f f3 [2] 70 e9 [2] 6e f4 [2] 6c f5 [2] 77 f3 [2] 6b f4 [2] 77 db }

  condition:
    any of them
}