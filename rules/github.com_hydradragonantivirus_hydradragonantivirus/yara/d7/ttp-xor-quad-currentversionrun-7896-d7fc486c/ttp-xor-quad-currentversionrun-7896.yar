rule TTP_XOR_QUAD_CurrentVersionRun_7896 {
  strings:
    $key_7896 = { 2b f9 [2] 0f f7 [2] 24 db [2] 0a f9 [2] 1e e2 [2] 11 f8 [2] 0f e5 [2] 0d e4 [2] 16 e2 [2] 0a e5 [2] 16 ca }

  condition:
    any of them
}