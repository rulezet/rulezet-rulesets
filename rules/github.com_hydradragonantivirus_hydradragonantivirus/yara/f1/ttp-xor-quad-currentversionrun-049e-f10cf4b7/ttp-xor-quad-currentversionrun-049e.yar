rule TTP_XOR_QUAD_CurrentVersionRun_049e {
  strings:
    $key_049e = { 57 f1 [2] 73 ff [2] 58 d3 [2] 76 f1 [2] 62 ea [2] 6d f0 [2] 73 ed [2] 71 ec [2] 6a ea [2] 76 ed [2] 6a c2 }

  condition:
    any of them
}