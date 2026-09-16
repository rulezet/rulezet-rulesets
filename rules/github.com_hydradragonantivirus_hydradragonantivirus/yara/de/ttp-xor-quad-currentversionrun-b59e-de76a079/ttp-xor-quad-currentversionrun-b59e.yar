rule TTP_XOR_QUAD_CurrentVersionRun_b59e {
  strings:
    $key_b59e = { e6 f1 [2] c2 ff [2] e9 d3 [2] c7 f1 [2] d3 ea [2] dc f0 [2] c2 ed [2] c0 ec [2] db ea [2] c7 ed [2] db c2 }

  condition:
    any of them
}