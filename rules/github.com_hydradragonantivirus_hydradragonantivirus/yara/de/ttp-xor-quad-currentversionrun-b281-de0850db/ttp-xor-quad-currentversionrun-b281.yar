rule TTP_XOR_QUAD_CurrentVersionRun_b281 {
  strings:
    $key_b281 = { e1 ee [2] c5 e0 [2] ee cc [2] c0 ee [2] d4 f5 [2] db ef [2] c5 f2 [2] c7 f3 [2] dc f5 [2] c0 f2 [2] dc dd }

  condition:
    any of them
}