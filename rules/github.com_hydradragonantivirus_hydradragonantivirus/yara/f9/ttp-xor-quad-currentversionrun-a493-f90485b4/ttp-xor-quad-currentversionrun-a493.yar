rule TTP_XOR_QUAD_CurrentVersionRun_a493 {
  strings:
    $key_a493 = { f7 fc [2] d3 f2 [2] f8 de [2] d6 fc [2] c2 e7 [2] cd fd [2] d3 e0 [2] d1 e1 [2] ca e7 [2] d6 e0 [2] ca cf }

  condition:
    any of them
}