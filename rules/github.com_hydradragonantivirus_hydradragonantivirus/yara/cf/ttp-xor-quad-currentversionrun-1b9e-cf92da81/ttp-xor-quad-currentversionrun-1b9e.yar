rule TTP_XOR_QUAD_CurrentVersionRun_1b9e {
  strings:
    $key_1b9e = { 48 f1 [2] 6c ff [2] 47 d3 [2] 69 f1 [2] 7d ea [2] 72 f0 [2] 6c ed [2] 6e ec [2] 75 ea [2] 69 ed [2] 75 c2 }

  condition:
    any of them
}