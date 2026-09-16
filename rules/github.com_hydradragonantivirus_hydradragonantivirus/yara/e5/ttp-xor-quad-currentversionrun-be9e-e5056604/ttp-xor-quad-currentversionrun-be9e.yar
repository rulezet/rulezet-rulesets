rule TTP_XOR_QUAD_CurrentVersionRun_be9e {
  strings:
    $key_be9e = { ed f1 [2] c9 ff [2] e2 d3 [2] cc f1 [2] d8 ea [2] d7 f0 [2] c9 ed [2] cb ec [2] d0 ea [2] cc ed [2] d0 c2 }

  condition:
    any of them
}