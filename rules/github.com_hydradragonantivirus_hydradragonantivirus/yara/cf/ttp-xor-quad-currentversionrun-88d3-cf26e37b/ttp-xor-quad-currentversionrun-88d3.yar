rule TTP_XOR_QUAD_CurrentVersionRun_88d3 {
  strings:
    $key_88d3 = { db bc [2] ff b2 [2] d4 9e [2] fa bc [2] ee a7 [2] e1 bd [2] ff a0 [2] fd a1 [2] e6 a7 [2] fa a0 [2] e6 8f }

  condition:
    any of them
}