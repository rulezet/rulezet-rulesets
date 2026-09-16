rule TTP_XOR_QUAD_CurrentVersionRun_ea81 {
  strings:
    $key_ea81 = { b9 ee [2] 9d e0 [2] b6 cc [2] 98 ee [2] 8c f5 [2] 83 ef [2] 9d f2 [2] 9f f3 [2] 84 f5 [2] 98 f2 [2] 84 dd }

  condition:
    any of them
}