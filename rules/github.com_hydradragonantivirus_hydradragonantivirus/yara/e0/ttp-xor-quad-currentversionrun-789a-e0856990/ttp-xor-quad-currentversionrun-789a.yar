rule TTP_XOR_QUAD_CurrentVersionRun_789a {
  strings:
    $key_789a = { 2b f5 [2] 0f fb [2] 24 d7 [2] 0a f5 [2] 1e ee [2] 11 f4 [2] 0f e9 [2] 0d e8 [2] 16 ee [2] 0a e9 [2] 16 c6 }

  condition:
    any of them
}