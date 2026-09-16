rule TTP_XOR_QUAD_CurrentVersionRun_d59e {
  strings:
    $key_d59e = { 86 f1 [2] a2 ff [2] 89 d3 [2] a7 f1 [2] b3 ea [2] bc f0 [2] a2 ed [2] a0 ec [2] bb ea [2] a7 ed [2] bb c2 }

  condition:
    any of them
}