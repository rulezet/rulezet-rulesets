rule TTP_XOR_QUAD_CurrentVersionRun_0781 {
  strings:
    $key_0781 = { 54 ee [2] 70 e0 [2] 5b cc [2] 75 ee [2] 61 f5 [2] 6e ef [2] 70 f2 [2] 72 f3 [2] 69 f5 [2] 75 f2 [2] 69 dd }

  condition:
    any of them
}