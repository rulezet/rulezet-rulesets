rule TTP_XOR_QUAD_CurrentVersionRun_b482 {
  strings:
    $key_b482 = { e7 ed [2] c3 e3 [2] e8 cf [2] c6 ed [2] d2 f6 [2] dd ec [2] c3 f1 [2] c1 f0 [2] da f6 [2] c6 f1 [2] da de }

  condition:
    any of them
}