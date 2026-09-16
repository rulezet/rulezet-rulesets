rule TTP_XOR_QUAD_CurrentVersionRun_479e {
  strings:
    $key_479e = { 14 f1 [2] 30 ff [2] 1b d3 [2] 35 f1 [2] 21 ea [2] 2e f0 [2] 30 ed [2] 32 ec [2] 29 ea [2] 35 ed [2] 29 c2 }

  condition:
    any of them
}