rule TTP_XOR_QUAD_CurrentVersionRun_a698 {
  strings:
    $key_a698 = { f5 f7 [2] d1 f9 [2] fa d5 [2] d4 f7 [2] c0 ec [2] cf f6 [2] d1 eb [2] d3 ea [2] c8 ec [2] d4 eb [2] c8 c4 }

  condition:
    any of them
}