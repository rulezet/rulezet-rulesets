rule TTP_XOR_QUAD_CurrentVersionRun_4d87 {
  strings:
    $key_4d87 = { 1e e8 [2] 3a e6 [2] 11 ca [2] 3f e8 [2] 2b f3 [2] 24 e9 [2] 3a f4 [2] 38 f5 [2] 23 f3 [2] 3f f4 [2] 23 db }

  condition:
    any of them
}