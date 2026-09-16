rule TTP_XOR_QUAD_CurrentVersionRun_7f9e {
  strings:
    $key_7f9e = { 2c f1 [2] 08 ff [2] 23 d3 [2] 0d f1 [2] 19 ea [2] 16 f0 [2] 08 ed [2] 0a ec [2] 11 ea [2] 0d ed [2] 11 c2 }

  condition:
    any of them
}