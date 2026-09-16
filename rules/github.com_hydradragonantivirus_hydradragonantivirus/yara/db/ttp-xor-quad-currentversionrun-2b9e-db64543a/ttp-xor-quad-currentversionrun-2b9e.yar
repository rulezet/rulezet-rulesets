rule TTP_XOR_QUAD_CurrentVersionRun_2b9e {
  strings:
    $key_2b9e = { 78 f1 [2] 5c ff [2] 77 d3 [2] 59 f1 [2] 4d ea [2] 42 f0 [2] 5c ed [2] 5e ec [2] 45 ea [2] 59 ed [2] 45 c2 }

  condition:
    any of them
}