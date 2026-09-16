rule TTP_XOR_QUAD_CurrentVersionRun_5c96 {
  strings:
    $key_5c96 = { 0f f9 [2] 2b f7 [2] 00 db [2] 2e f9 [2] 3a e2 [2] 35 f8 [2] 2b e5 [2] 29 e4 [2] 32 e2 [2] 2e e5 [2] 32 ca }

  condition:
    any of them
}