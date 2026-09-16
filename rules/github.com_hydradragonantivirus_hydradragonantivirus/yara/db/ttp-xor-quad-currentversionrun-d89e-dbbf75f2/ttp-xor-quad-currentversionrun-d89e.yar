rule TTP_XOR_QUAD_CurrentVersionRun_d89e {
  strings:
    $key_d89e = { 8b f1 [2] af ff [2] 84 d3 [2] aa f1 [2] be ea [2] b1 f0 [2] af ed [2] ad ec [2] b6 ea [2] aa ed [2] b6 c2 }

  condition:
    any of them
}