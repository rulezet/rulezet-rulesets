rule TTP_XOR_QUAD_CurrentVersionRun_5fbc {
  strings:
    $key_5fbc = { 0c d3 [2] 28 dd [2] 03 f1 [2] 2d d3 [2] 39 c8 [2] 36 d2 [2] 28 cf [2] 2a ce [2] 31 c8 [2] 2d cf [2] 31 e0 }

  condition:
    any of them
}