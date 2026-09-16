rule TTP_XOR_QUAD_CurrentVersionRun_6b81 {
  strings:
    $key_6b81 = { 38 ee [2] 1c e0 [2] 37 cc [2] 19 ee [2] 0d f5 [2] 02 ef [2] 1c f2 [2] 1e f3 [2] 05 f5 [2] 19 f2 [2] 05 dd }

  condition:
    any of them
}