rule TTP_XOR_QUAD_CurrentVersionRun_2a9e {
  strings:
    $key_2a9e = { 79 f1 [2] 5d ff [2] 76 d3 [2] 58 f1 [2] 4c ea [2] 43 f0 [2] 5d ed [2] 5f ec [2] 44 ea [2] 58 ed [2] 44 c2 }

  condition:
    any of them
}