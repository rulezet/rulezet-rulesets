rule TTP_XOR_QUAD_CurrentVersionRun_d49e {
  strings:
    $key_d49e = { 87 f1 [2] a3 ff [2] 88 d3 [2] a6 f1 [2] b2 ea [2] bd f0 [2] a3 ed [2] a1 ec [2] ba ea [2] a6 ed [2] ba c2 }

  condition:
    any of them
}