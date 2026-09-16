rule TTP_XOR_QUAD_CurrentVersionRun_a1b2 {
  strings:
    $key_a1b2 = { f2 dd [2] d6 d3 [2] fd ff [2] d3 dd [2] c7 c6 [2] c8 dc [2] d6 c1 [2] d4 c0 [2] cf c6 [2] d3 c1 [2] cf ee }

  condition:
    any of them
}