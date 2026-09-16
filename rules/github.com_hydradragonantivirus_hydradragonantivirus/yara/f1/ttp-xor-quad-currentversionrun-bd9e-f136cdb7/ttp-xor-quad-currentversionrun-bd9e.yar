rule TTP_XOR_QUAD_CurrentVersionRun_bd9e {
  strings:
    $key_bd9e = { ee f1 [2] ca ff [2] e1 d3 [2] cf f1 [2] db ea [2] d4 f0 [2] ca ed [2] c8 ec [2] d3 ea [2] cf ed [2] d3 c2 }

  condition:
    any of them
}