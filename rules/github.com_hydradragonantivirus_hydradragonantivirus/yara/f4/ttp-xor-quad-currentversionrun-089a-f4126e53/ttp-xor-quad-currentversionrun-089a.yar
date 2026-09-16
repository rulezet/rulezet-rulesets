rule TTP_XOR_QUAD_CurrentVersionRun_089a {
  strings:
    $key_089a = { 5b f5 [2] 7f fb [2] 54 d7 [2] 7a f5 [2] 6e ee [2] 61 f4 [2] 7f e9 [2] 7d e8 [2] 66 ee [2] 7a e9 [2] 66 c6 }

  condition:
    any of them
}