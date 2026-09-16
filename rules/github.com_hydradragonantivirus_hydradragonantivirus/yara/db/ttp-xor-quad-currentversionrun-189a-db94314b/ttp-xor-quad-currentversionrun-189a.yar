rule TTP_XOR_QUAD_CurrentVersionRun_189a {
  strings:
    $key_189a = { 4b f5 [2] 6f fb [2] 44 d7 [2] 6a f5 [2] 7e ee [2] 71 f4 [2] 6f e9 [2] 6d e8 [2] 76 ee [2] 6a e9 [2] 76 c6 }

  condition:
    any of them
}