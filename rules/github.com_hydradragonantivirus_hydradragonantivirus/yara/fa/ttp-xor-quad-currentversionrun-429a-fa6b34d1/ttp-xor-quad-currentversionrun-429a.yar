rule TTP_XOR_QUAD_CurrentVersionRun_429a {
  strings:
    $key_429a = { 11 f5 [2] 35 fb [2] 1e d7 [2] 30 f5 [2] 24 ee [2] 2b f4 [2] 35 e9 [2] 37 e8 [2] 2c ee [2] 30 e9 [2] 2c c6 }

  condition:
    any of them
}