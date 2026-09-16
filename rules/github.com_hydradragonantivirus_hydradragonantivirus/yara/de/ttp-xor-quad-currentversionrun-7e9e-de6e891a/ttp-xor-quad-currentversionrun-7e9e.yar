rule TTP_XOR_QUAD_CurrentVersionRun_7e9e {
  strings:
    $key_7e9e = { 2d f1 [2] 09 ff [2] 22 d3 [2] 0c f1 [2] 18 ea [2] 17 f0 [2] 09 ed [2] 0b ec [2] 10 ea [2] 0c ed [2] 10 c2 }

  condition:
    any of them
}