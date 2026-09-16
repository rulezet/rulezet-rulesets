rule TTP_XOR_QUAD_CurrentVersionRun_6a9e {
  strings:
    $key_6a9e = { 39 f1 [2] 1d ff [2] 36 d3 [2] 18 f1 [2] 0c ea [2] 03 f0 [2] 1d ed [2] 1f ec [2] 04 ea [2] 18 ed [2] 04 c2 }

  condition:
    any of them
}