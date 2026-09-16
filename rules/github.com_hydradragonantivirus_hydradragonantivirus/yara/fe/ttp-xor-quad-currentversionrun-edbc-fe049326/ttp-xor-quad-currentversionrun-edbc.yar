rule TTP_XOR_QUAD_CurrentVersionRun_edbc {
  strings:
    $key_edbc = { be d3 [2] 9a dd [2] b1 f1 [2] 9f d3 [2] 8b c8 [2] 84 d2 [2] 9a cf [2] 98 ce [2] 83 c8 [2] 9f cf [2] 83 e0 }

  condition:
    any of them
}