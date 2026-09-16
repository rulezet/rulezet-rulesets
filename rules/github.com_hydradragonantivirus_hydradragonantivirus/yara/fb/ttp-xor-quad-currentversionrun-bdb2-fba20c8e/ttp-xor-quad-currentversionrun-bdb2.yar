rule TTP_XOR_QUAD_CurrentVersionRun_bdb2 {
  strings:
    $key_bdb2 = { ee dd [2] ca d3 [2] e1 ff [2] cf dd [2] db c6 [2] d4 dc [2] ca c1 [2] c8 c0 [2] d3 c6 [2] cf c1 [2] d3 ee }

  condition:
    any of them
}