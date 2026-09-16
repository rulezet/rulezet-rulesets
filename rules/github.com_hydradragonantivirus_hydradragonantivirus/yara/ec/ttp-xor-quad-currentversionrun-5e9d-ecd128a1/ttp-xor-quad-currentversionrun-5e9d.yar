rule TTP_XOR_QUAD_CurrentVersionRun_5e9d {
  strings:
    $key_5e9d = { 0d f2 [2] 29 fc [2] 02 d0 [2] 2c f2 [2] 38 e9 [2] 37 f3 [2] 29 ee [2] 2b ef [2] 30 e9 [2] 2c ee [2] 30 c1 }

  condition:
    any of them
}