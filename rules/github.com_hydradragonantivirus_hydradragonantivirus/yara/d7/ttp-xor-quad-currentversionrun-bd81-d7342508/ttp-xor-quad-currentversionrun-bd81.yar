rule TTP_XOR_QUAD_CurrentVersionRun_bd81 {
  strings:
    $key_bd81 = { ee ee [2] ca e0 [2] e1 cc [2] cf ee [2] db f5 [2] d4 ef [2] ca f2 [2] c8 f3 [2] d3 f5 [2] cf f2 [2] d3 dd }

  condition:
    any of them
}