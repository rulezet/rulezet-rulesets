rule TTP_XOR_QUAD_CurrentVersionRun_eb9e {
  strings:
    $key_eb9e = { b8 f1 [2] 9c ff [2] b7 d3 [2] 99 f1 [2] 8d ea [2] 82 f0 [2] 9c ed [2] 9e ec [2] 85 ea [2] 99 ed [2] 85 c2 }

  condition:
    any of them
}