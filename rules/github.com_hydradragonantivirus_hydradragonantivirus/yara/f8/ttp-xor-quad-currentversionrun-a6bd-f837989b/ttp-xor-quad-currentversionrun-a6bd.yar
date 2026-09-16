rule TTP_XOR_QUAD_CurrentVersionRun_a6bd {
  strings:
    $key_a6bd = { f5 d2 [2] d1 dc [2] fa f0 [2] d4 d2 [2] c0 c9 [2] cf d3 [2] d1 ce [2] d3 cf [2] c8 c9 [2] d4 ce [2] c8 e1 }

  condition:
    any of them
}