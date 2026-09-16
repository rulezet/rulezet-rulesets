rule TTP_XOR_QUAD_CurrentVersionRun_e79e {
  strings:
    $key_e79e = { b4 f1 [2] 90 ff [2] bb d3 [2] 95 f1 [2] 81 ea [2] 8e f0 [2] 90 ed [2] 92 ec [2] 89 ea [2] 95 ed [2] 89 c2 }

  condition:
    any of them
}