rule TTP_XOR_QUAD_CurrentVersionRun_ea9e {
  strings:
    $key_ea9e = { b9 f1 [2] 9d ff [2] b6 d3 [2] 98 f1 [2] 8c ea [2] 83 f0 [2] 9d ed [2] 9f ec [2] 84 ea [2] 98 ed [2] 84 c2 }

  condition:
    any of them
}