rule TTP_XOR_QUAD_CurrentVersionRun_159a {
  strings:
    $key_159a = { 46 f5 [2] 62 fb [2] 49 d7 [2] 67 f5 [2] 73 ee [2] 7c f4 [2] 62 e9 [2] 60 e8 [2] 7b ee [2] 67 e9 [2] 7b c6 }

  condition:
    any of them
}