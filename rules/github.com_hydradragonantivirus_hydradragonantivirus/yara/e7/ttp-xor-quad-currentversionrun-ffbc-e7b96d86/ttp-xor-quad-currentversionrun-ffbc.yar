rule TTP_XOR_QUAD_CurrentVersionRun_ffbc {
  strings:
    $key_ffbc = { ac d3 [2] 88 dd [2] a3 f1 [2] 8d d3 [2] 99 c8 [2] 96 d2 [2] 88 cf [2] 8a ce [2] 91 c8 [2] 8d cf [2] 91 e0 }

  condition:
    any of them
}