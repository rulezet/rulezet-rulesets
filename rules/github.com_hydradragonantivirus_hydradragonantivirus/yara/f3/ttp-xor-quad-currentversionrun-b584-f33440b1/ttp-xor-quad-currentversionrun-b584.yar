rule TTP_XOR_QUAD_CurrentVersionRun_b584 {
  strings:
    $key_b584 = { e6 eb [2] c2 e5 [2] e9 c9 [2] c7 eb [2] d3 f0 [2] dc ea [2] c2 f7 [2] c0 f6 [2] db f0 [2] c7 f7 [2] db d8 }

  condition:
    any of them
}