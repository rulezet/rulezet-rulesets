rule TTP_XOR_QUAD_CurrentVersionRun_7d96 {
  strings:
    $key_7d96 = { 2e f9 [2] 0a f7 [2] 21 db [2] 0f f9 [2] 1b e2 [2] 14 f8 [2] 0a e5 [2] 08 e4 [2] 13 e2 [2] 0f e5 [2] 13 ca }

  condition:
    any of them
}