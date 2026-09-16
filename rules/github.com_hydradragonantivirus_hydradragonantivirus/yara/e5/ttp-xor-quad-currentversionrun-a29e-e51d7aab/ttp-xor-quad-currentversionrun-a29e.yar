rule TTP_XOR_QUAD_CurrentVersionRun_a29e {
  strings:
    $key_a29e = { f1 f1 [2] d5 ff [2] fe d3 [2] d0 f1 [2] c4 ea [2] cb f0 [2] d5 ed [2] d7 ec [2] cc ea [2] d0 ed [2] cc c2 }

  condition:
    any of them
}