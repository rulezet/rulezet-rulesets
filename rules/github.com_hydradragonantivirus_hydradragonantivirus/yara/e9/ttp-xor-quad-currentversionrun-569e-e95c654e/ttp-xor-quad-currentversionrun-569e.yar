rule TTP_XOR_QUAD_CurrentVersionRun_569e {
  strings:
    $key_569e = { 05 f1 [2] 21 ff [2] 0a d3 [2] 24 f1 [2] 30 ea [2] 3f f0 [2] 21 ed [2] 23 ec [2] 38 ea [2] 24 ed [2] 38 c2 }

  condition:
    any of them
}