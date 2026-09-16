rule TTP_XOR_QUAD_CurrentVersionRun_b293 {
  strings:
    $key_b293 = { e1 fc [2] c5 f2 [2] ee de [2] c0 fc [2] d4 e7 [2] db fd [2] c5 e0 [2] c7 e1 [2] dc e7 [2] c0 e0 [2] dc cf }

  condition:
    any of them
}