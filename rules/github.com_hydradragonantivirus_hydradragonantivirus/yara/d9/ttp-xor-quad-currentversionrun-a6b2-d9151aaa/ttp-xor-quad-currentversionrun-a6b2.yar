rule TTP_XOR_QUAD_CurrentVersionRun_a6b2 {
  strings:
    $key_a6b2 = { f5 dd [2] d1 d3 [2] fa ff [2] d4 dd [2] c0 c6 [2] cf dc [2] d1 c1 [2] d3 c0 [2] c8 c6 [2] d4 c1 [2] c8 ee }

  condition:
    any of them
}