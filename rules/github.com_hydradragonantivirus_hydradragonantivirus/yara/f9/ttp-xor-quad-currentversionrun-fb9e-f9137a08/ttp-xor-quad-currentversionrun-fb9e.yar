rule TTP_XOR_QUAD_CurrentVersionRun_fb9e {
  strings:
    $key_fb9e = { a8 f1 [2] 8c ff [2] a7 d3 [2] 89 f1 [2] 9d ea [2] 92 f0 [2] 8c ed [2] 8e ec [2] 95 ea [2] 89 ed [2] 95 c2 }

  condition:
    any of them
}