rule TTP_XOR_QUAD_CurrentVersionRun_a19e {
  strings:
    $key_a19e = { f2 f1 [2] d6 ff [2] fd d3 [2] d3 f1 [2] c7 ea [2] c8 f0 [2] d6 ed [2] d4 ec [2] cf ea [2] d3 ed [2] cf c2 }

  condition:
    any of them
}