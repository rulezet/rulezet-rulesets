rule TTP_XOR_QUAD_CurrentVersionRun_689a {
  strings:
    $key_689a = { 3b f5 [2] 1f fb [2] 34 d7 [2] 1a f5 [2] 0e ee [2] 01 f4 [2] 1f e9 [2] 1d e8 [2] 06 ee [2] 1a e9 [2] 06 c6 }

  condition:
    any of them
}