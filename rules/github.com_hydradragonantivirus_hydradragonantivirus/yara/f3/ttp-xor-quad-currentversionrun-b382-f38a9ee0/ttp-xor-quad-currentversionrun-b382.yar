rule TTP_XOR_QUAD_CurrentVersionRun_b382 {
  strings:
    $key_b382 = { e0 ed [2] c4 e3 [2] ef cf [2] c1 ed [2] d5 f6 [2] da ec [2] c4 f1 [2] c6 f0 [2] dd f6 [2] c1 f1 [2] dd de }

  condition:
    any of them
}