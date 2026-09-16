rule TTP_XOR_QUAD_CurrentVersionRun_0381 {
  strings:
    $key_0381 = { 50 ee [2] 74 e0 [2] 5f cc [2] 71 ee [2] 65 f5 [2] 6a ef [2] 74 f2 [2] 76 f3 [2] 6d f5 [2] 71 f2 [2] 6d dd }

  condition:
    any of them
}