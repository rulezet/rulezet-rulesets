rule TTP_XOR_QUAD_CurrentVersionRun_fc9e {
  strings:
    $key_fc9e = { af f1 [2] 8b ff [2] a0 d3 [2] 8e f1 [2] 9a ea [2] 95 f0 [2] 8b ed [2] 89 ec [2] 92 ea [2] 8e ed [2] 92 c2 }

  condition:
    any of them
}