rule TTP_XOR_QUAD_CurrentVersionRun_159e {
  strings:
    $key_159e = { 46 f1 [2] 62 ff [2] 49 d3 [2] 67 f1 [2] 73 ea [2] 7c f0 [2] 62 ed [2] 60 ec [2] 7b ea [2] 67 ed [2] 7b c2 }

  condition:
    any of them
}