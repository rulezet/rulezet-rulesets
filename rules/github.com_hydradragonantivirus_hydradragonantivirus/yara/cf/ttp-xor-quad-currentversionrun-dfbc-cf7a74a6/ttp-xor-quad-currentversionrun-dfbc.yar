rule TTP_XOR_QUAD_CurrentVersionRun_dfbc {
  strings:
    $key_dfbc = { 8c d3 [2] a8 dd [2] 83 f1 [2] ad d3 [2] b9 c8 [2] b6 d2 [2] a8 cf [2] aa ce [2] b1 c8 [2] ad cf [2] b1 e0 }

  condition:
    any of them
}