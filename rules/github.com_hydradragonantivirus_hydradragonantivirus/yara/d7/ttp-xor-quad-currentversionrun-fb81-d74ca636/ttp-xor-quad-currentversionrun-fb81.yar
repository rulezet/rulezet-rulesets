rule TTP_XOR_QUAD_CurrentVersionRun_fb81 {
  strings:
    $key_fb81 = { a8 ee [2] 8c e0 [2] a7 cc [2] 89 ee [2] 9d f5 [2] 92 ef [2] 8c f2 [2] 8e f3 [2] 95 f5 [2] 89 f2 [2] 95 dd }

  condition:
    any of them
}