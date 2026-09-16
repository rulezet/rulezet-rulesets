rule TTP_XOR_QUAD_CurrentVersionRun_b183 {
  strings:
    $key_b183 = { e2 ec [2] c6 e2 [2] ed ce [2] c3 ec [2] d7 f7 [2] d8 ed [2] c6 f0 [2] c4 f1 [2] df f7 [2] c3 f0 [2] df df }

  condition:
    any of them
}