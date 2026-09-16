rule TTP_XOR_QUAD_CurrentVersionRun_fdbc {
  strings:
    $key_fdbc = { ae d3 [2] 8a dd [2] a1 f1 [2] 8f d3 [2] 9b c8 [2] 94 d2 [2] 8a cf [2] 88 ce [2] 93 c8 [2] 8f cf [2] 93 e0 }

  condition:
    any of them
}