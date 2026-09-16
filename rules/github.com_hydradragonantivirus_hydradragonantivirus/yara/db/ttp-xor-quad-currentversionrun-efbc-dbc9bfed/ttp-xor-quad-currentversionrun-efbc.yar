rule TTP_XOR_QUAD_CurrentVersionRun_efbc {
  strings:
    $key_efbc = { bc d3 [2] 98 dd [2] b3 f1 [2] 9d d3 [2] 89 c8 [2] 86 d2 [2] 98 cf [2] 9a ce [2] 81 c8 [2] 9d cf [2] 81 e0 }

  condition:
    any of them
}