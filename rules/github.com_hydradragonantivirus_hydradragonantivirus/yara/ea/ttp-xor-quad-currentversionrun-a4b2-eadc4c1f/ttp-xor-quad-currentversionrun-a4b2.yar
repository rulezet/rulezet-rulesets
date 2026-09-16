rule TTP_XOR_QUAD_CurrentVersionRun_a4b2 {
  strings:
    $key_a4b2 = { f7 dd [2] d3 d3 [2] f8 ff [2] d6 dd [2] c2 c6 [2] cd dc [2] d3 c1 [2] d1 c0 [2] ca c6 [2] d6 c1 [2] ca ee }

  condition:
    any of them
}