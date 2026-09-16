rule TTP_XOR_QUAD_CurrentVersionRun_4b81 {
  strings:
    $key_4b81 = { 18 ee [2] 3c e0 [2] 17 cc [2] 39 ee [2] 2d f5 [2] 22 ef [2] 3c f2 [2] 3e f3 [2] 25 f5 [2] 39 f2 [2] 25 dd }

  condition:
    any of them
}