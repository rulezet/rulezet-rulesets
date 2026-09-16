rule TTP_XOR_QUAD_CurrentVersionRun_f19e {
  strings:
    $key_f19e = { a2 f1 [2] 86 ff [2] ad d3 [2] 83 f1 [2] 97 ea [2] 98 f0 [2] 86 ed [2] 84 ec [2] 9f ea [2] 83 ed [2] 9f c2 }

  condition:
    any of them
}