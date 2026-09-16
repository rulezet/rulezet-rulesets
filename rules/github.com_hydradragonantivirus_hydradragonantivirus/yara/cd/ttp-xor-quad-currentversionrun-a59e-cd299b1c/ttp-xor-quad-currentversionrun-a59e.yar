rule TTP_XOR_QUAD_CurrentVersionRun_a59e {
  strings:
    $key_a59e = { f6 f1 [2] d2 ff [2] f9 d3 [2] d7 f1 [2] c3 ea [2] cc f0 [2] d2 ed [2] d0 ec [2] cb ea [2] d7 ed [2] cb c2 }

  condition:
    any of them
}