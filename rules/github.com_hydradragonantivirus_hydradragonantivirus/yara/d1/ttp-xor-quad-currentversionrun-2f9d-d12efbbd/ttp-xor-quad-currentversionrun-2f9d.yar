rule TTP_XOR_QUAD_CurrentVersionRun_2f9d {
  strings:
    $key_2f9d = { 7c f2 [2] 58 fc [2] 73 d0 [2] 5d f2 [2] 49 e9 [2] 46 f3 [2] 58 ee [2] 5a ef [2] 41 e9 [2] 5d ee [2] 41 c1 }

  condition:
    any of them
}