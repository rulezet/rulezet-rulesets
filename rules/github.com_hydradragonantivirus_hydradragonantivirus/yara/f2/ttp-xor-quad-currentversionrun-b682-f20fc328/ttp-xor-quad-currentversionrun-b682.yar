rule TTP_XOR_QUAD_CurrentVersionRun_b682 {
  strings:
    $key_b682 = { e5 ed [2] c1 e3 [2] ea cf [2] c4 ed [2] d0 f6 [2] df ec [2] c1 f1 [2] c3 f0 [2] d8 f6 [2] c4 f1 [2] d8 de }

  condition:
    any of them
}