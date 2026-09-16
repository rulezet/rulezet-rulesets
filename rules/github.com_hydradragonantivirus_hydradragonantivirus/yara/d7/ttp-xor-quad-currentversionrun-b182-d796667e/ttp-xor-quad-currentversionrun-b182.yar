rule TTP_XOR_QUAD_CurrentVersionRun_b182 {
  strings:
    $key_b182 = { e2 ed [2] c6 e3 [2] ed cf [2] c3 ed [2] d7 f6 [2] d8 ec [2] c6 f1 [2] c4 f0 [2] df f6 [2] c3 f1 [2] df de }

  condition:
    any of them
}