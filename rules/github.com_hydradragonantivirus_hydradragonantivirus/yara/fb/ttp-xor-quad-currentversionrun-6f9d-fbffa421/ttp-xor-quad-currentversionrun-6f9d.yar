rule TTP_XOR_QUAD_CurrentVersionRun_6f9d {
  strings:
    $key_6f9d = { 3c f2 [2] 18 fc [2] 33 d0 [2] 1d f2 [2] 09 e9 [2] 06 f3 [2] 18 ee [2] 1a ef [2] 01 e9 [2] 1d ee [2] 01 c1 }

  condition:
    any of them
}