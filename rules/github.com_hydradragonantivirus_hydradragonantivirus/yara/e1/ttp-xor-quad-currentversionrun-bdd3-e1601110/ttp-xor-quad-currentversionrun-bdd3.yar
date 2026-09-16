rule TTP_XOR_QUAD_CurrentVersionRun_bdd3 {
  strings:
    $key_bdd3 = { ee bc [2] ca b2 [2] e1 9e [2] cf bc [2] db a7 [2] d4 bd [2] ca a0 [2] c8 a1 [2] d3 a7 [2] cf a0 [2] d3 8f }

  condition:
    any of them
}