rule TTP_XOR_QUAD_CurrentVersionRun_a793 {
  strings:
    $key_a793 = { f4 fc [2] d0 f2 [2] fb de [2] d5 fc [2] c1 e7 [2] ce fd [2] d0 e0 [2] d2 e1 [2] c9 e7 [2] d5 e0 [2] c9 cf }

  condition:
    any of them
}