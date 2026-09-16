rule TTP_XOR_QUAD_CurrentVersionRun_759e {
  strings:
    $key_759e = { 26 f1 [2] 02 ff [2] 29 d3 [2] 07 f1 [2] 13 ea [2] 1c f0 [2] 02 ed [2] 00 ec [2] 1b ea [2] 07 ed [2] 1b c2 }

  condition:
    any of them
}